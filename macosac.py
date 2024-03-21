#!/usr/bin/env python3
#
# macosac.py
# macOS Artifact Collector can collect forensics artifact files on macOS.
# Please use other tools for analyzing (e.g. AutoMacTC, mac_apt, etc).
#
# Copyright 2020 Minoru Kobayashi <unknownbit@gmail.com> (@unkn0wnbit)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from __future__ import annotations

import argparse
import collections
import datetime
import glob
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

import xattr

try:
    import ConfigParser
    py3_flag = False
except ImportError:
    import configparser
    py3_flag = True

# global variables
cmd_rsync = '/usr/bin/rsync'
cmd_tmutil = '/usr/bin/tmutil'
cmd_hdiutil = '/usr/bin/hdiutil'
debug_mode = False
dryrun_mode = False
file_debug = None

target_volume = collections.namedtuple("target_volume", "name root_path")


# setup arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Collects macOS forensic artifacts.")
    parser.add_argument('-o', '--outputdir', action='store', default=None,
                        help='Output directory for collected artifacts')
    parser.add_argument('-t', '--outputtype', action='store', default='dir',
                        help='Output type: dir, dmg or ro-dmg. "ro-dmg" means "Read Only DMG". Converts a regular dmg to UDRO format after collecting artifacts. (default: dir)')
    parser.add_argument('-l', '--list', action='store_true', default=False,
                        help='List categories which are defined in macosac.ini')
    parser.add_argument('-c', '--categories', action='store', default='all',
                        help='Specify comma separated categories (default: all).')
    parser.add_argument('-ls', '--localsnapshots', action='store_true', default=False,
                        help='Retrieve artifacts from local snapshots.')
    parser.add_argument('-tm', '--timemachine', action='store_true', default=False,
                        help='Retrieve artifacts from Time Machine bakcups.')
    parser.add_argument('-ts', '--timestamp', action='store', default='0000-00-00-000000',
                        help='Specify the timestamp of localsnapshots/Time Machine backups to start collecting: YYYY-MM-DD-hhmmss (default: 0000-00-00-000000 It means to collect all backups)')
    parser.add_argument('-tz', '--timezone', action='store', default='UTC0',
                        help='Timezone: e.g. UTC0, JST-9 (default: UTC0)')
    parser.add_argument('-vn', '--volumename', action='store', default='',
                        help='Disk volume name macOS is installed (default: macOS < 10.15: "Macintosh HD", macOS >= 10.15 (Intel): "Macintosh HD - Data", macOS >= 10.15 (Apple Silicon): "Data")')
    parser.add_argument('--use-builtincopy', action='store_true', default=False,
                        help='Use a built-in copy function instead of rsync.')
    # parser.add_argument('--force', action='store_true', default=False,
    #                     help='Enable to overwrite existing data.')
    parser.add_argument('--debug', action='store_true', default=False, help='Enable debug mode.')
    parser.add_argument('--dry-run', action='store_true', default=False, help='Enable dry-run mode. Artifact files are NOT copied.')
    args = parser.parse_args()

    return args


def dbg_print(msg):
    if msg and debug_mode:
        print('{}'.format(msg))
        if file_debug:
            open(file_debug, 'a').write('{}\n'.format(msg))
            return True

    return False


def determine_default_volume() -> str:
    release, version_info, machine = platform.mac_ver()
    release = float(release)
    dbg_print('macOS release: {}, version_info: {}, machine: {}'.format(release, version_info, machine))
    if release < 10.15:
        return 'Macintosh HD'
    elif release >= 10.15 and machine == 'x86_64':
        return 'Macintosh HD - Data'
    elif release >= 10.15 and machine == 'arm64':
        return 'Data'
    else:
        sys.exit('Unknown macOS version or machine type: {} {} {}'.format(release, version_info, machine))


# create and mount DMG file to copy artifacts
def create_and_mount_dmg(dmg_path, volname, data_size):
    verify_codesign(cmd_hdiutil)
    # create dmg file
    # dmg_size = data_size + (100 * 1024 * 1024)  # increase 100MB for metadata attributes
    dmg_size = data_size * 1.1  # increase 10% of size for metadata attributes
    if dmg_size < 1 * 1024 * 1024:  # 1MB
        dmg_size = 1 * 1024 * 1024
    dbg_print('dmg_path: {}\nvolname: {}\ndata_size: {}\ndmg_size: {}'.format(dmg_path, volname, data_size, dmg_size))
    # return_code = subprocess.call([cmd_hdiutil, 'create', '-size', str(dmg_size), '-fs', 'HFS+', '-volname', volname, dmg_path])
    return_code = subprocess.call([cmd_hdiutil, 'create', '-size', str(dmg_size), '-fs', 'APFS', '-volname', volname, dmg_path])
    if return_code:
        sys.exit('Failed to create dmg file: {}'.format(dmg_path))

    # mount dmg file
    return_code = subprocess.call([cmd_hdiutil, 'attach', dmg_path])
    if not return_code:
        return True
    else:
        sys.exit('Failed to mount dmg file: {}'.format(dmg_path))


# Unmount DMG file
def unmount_dmg(volname):
    dbg_print('Unmount: {}'.format(os.path.join('/Volumes', volname)))
    # return_code = subprocess.call([cmd_hdiutil, 'unmount', os.path.join('/Volumes', volname)])
    return_code = subprocess.call([cmd_hdiutil, 'detach', os.path.join('/Volumes', volname)])
    if not return_code:
        return True
    else:
        sys.exit('Failed to unmount volume: {}'.format(os.path.join('/Volumes', volname)))


# Convert dmg file
def convert_dmg(dmg_path, remove_orig=True):
    split_path = dmg_path.split('.')
    split_path[-2] = split_path[-2] + '_ro'
    ro_dmg_path = '.'.join(split_path)
    dbg_print('Convert: {} -> {}'.format(dmg_path, ro_dmg_path))
    return_code = subprocess.call([cmd_hdiutil, 'convert', dmg_path, '-format', 'UDRO', '-o', ro_dmg_path])

    if remove_orig:
        os.remove(dmg_path)

    if not return_code:
        return True
    else:
        sys.exit('Failed to convert DMG file: {}'.format(dmg_path))


# Retrieve file stat
# Artifact files will lose theire MACB timestamp if rsync/cp copies them.
def retrieve_file_stat(outputdir, artifact_list, timezone):
    os.environ['TZ'] = timezone
    time.tzset()

    record_fields = ['file_path', 'm_time', 'a_time', 'c_time', 'b_time', 'size', 'uid', 'gid']
    record = dict()
    file_stat_list = list()
    total_size = 0

    try:
        file_stat_list.append(','.join(record_fields))

        for file in artifact_list:
            try:
                file_stat = os.lstat(file)
                record = collections.OrderedDict((field, '') for field in record_fields)

                record['file_path'] = file
                record['m_time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(file_stat.st_mtime)) + '.' + "{0:.6f}".format(file_stat.st_mtime).split('.')[1] + ' ' + time.strftime('%Z%z')
                record['a_time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(file_stat.st_atime)) + '.' + "{0:.6f}".format(file_stat.st_atime).split('.')[1] + ' ' + time.strftime('%Z%z')
                record['c_time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(file_stat.st_ctime)) + '.' + "{0:.6f}".format(file_stat.st_ctime).split('.')[1] + ' ' + time.strftime('%Z%z')
                record['b_time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(file_stat.st_birthtime)) + '.' + "{0:.6f}".format(file_stat.st_birthtime).split('.')[1] + ' ' + time.strftime('%Z%z')
                record['size'] = file_stat.st_size
                record['uid'] = file_stat.st_uid
                record['gid'] = file_stat.st_gid
                total_size = total_size + (-(-file_stat.st_size // os.statvfs(outputdir).f_frsize) * os.statvfs(outputdir).f_frsize)

                file_stat_list.append(','.join(map(lambda x: str(x), record.values())))
            except Exception as e:
                print('{}'.format(e))

        print("total_size:  {}".format(total_size))
        return file_stat_list, total_size

    except Exception as e:
        print('{}'.format(e))
        return None, 0


def save_file_stat(outputdir, file_stat_list):
    try:
        with open(os.path.join(outputdir, 'artifact_file_stat.csv'), 'wt') as fp:
            fp.write('\n'.join(file_stat_list))
    except OSError as err:
        sys.exit('Cannot write artifact_file_stat.csv: {}'.format(err))


def write_no_log_fseventsd_file(outputdir):
    try:
        os.makedirs(os.path.join(outputdir, '.fseventsd'))
        with open(os.path.join(outputdir, '.fseventsd', 'no_log'), 'w') as fp:
            fp.close()
    except OSError as err:
        pass
        #sys.exit('Cannot create .fseventsd/no_log file : {}'.format(err))


# get timestamp list that consist of local snapshots and Time Machine backups
def get_backup_targets(timestamp, timemachine, localsnapshots, volumename):
    '''Returns list of namedtuples of type target_volume'''
    backup_list = list()
    verify_codesign(cmd_tmutil)

    # Time Machine backups
    if timemachine:
        ps_tmutil = subprocess.Popen([cmd_tmutil, 'listbackups'], stdout=subprocess.PIPE)
        backups, err = ps_tmutil.communicate()

        if not ps_tmutil.returncode:
            backups = backups.decode() if type(backups) is bytes else backups  # Python 3 returns bytes
            for backup in backups.split('\n'):
                tmbackup_volume = re.match(r'/Volumes/.*/Backups.backupdb/.*/(?P<timestamp>\d{4}\-\d{2}\-\d{2}\-\d{6})', backup) or \
                                  re.match(r'/Volumes/.timemachine/[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/\d{4}\-\d{2}\-\d{2}\-\d{6}.backup/(?P<timestamp>\d{4}\-\d{2}\-\d{2}\-\d{6}).backup', backup)
                if tmbackup_volume and tmbackup_volume['timestamp'] >= timestamp:
                    backup_list.append(target_volume('TM-Backup-' + tmbackup_volume['timestamp'], backup + '/' + volumename))

    # local snapshots
    if localsnapshots:
        ps_tmutil = subprocess.Popen([cmd_tmutil, 'listlocalsnapshots', '/'], stdout=subprocess.PIPE)
        snapshots, err = ps_tmutil.communicate()

        if not ps_tmutil.returncode:
            snapshots = snapshots.decode() if type(snapshots) is bytes else snapshots
            for snapshot in snapshots.split('\n'):
                snapshot_volume = re.match(r'com.apple.TimeMachine.(?P<timestamp>\d{4}\-\d{2}\-\d{2}\-\d{6})', snapshot) or \
                                  re.match(r'/Volumes/com.apple.TimeMachine.localsnapshots/Backups.backupdb/.+/(?P<timestamp>\d{4}\-\d{2}\-\d{2}\-\d{6})/.*', snapshot)
                if snapshot_volume and snapshot_volume['timestamp'] >= timestamp:
                    ps_tmutil = subprocess.Popen([cmd_tmutil, 'mountlocalsnapshots', '/', snapshot_volume['timestamp']], stdout=subprocess.PIPE)
                    mount_result, e = ps_tmutil.communicate()
                    if not ps_tmutil.returncode:
                        mount_result = mount_result.decode() if type(mount_result) is bytes else mount_result
                        if mount_result.endswith("(\n)\n"):  # Failed without error, this happens on some systems, reason unknown!
                            print('Failed to mount snapshot ' + snapshot_volume['timestamp'])
                            continue
                        try:
                            # Sometimes output contains unicode chars rendered as \Uxxxx, which won't be recognized as a valid path and needs to be fixed
                            #  Mounted local snapshots: (
                            #    "/Volumes/com.apple.TimeMachine.localsnapshots/Backups.backupdb/Batman\U2019s Mac/2021-08-13-012712/Macintosh HD - Data"
                            #  )
                            # Need to convert the \U2019 into it's native form which is right-single-quote character
                            snap_mounted_path = mount_result.split('\n')[1].split('"')[1]
                            if not os.path.exists(snap_mounted_path):  # needs fixing - see comment above
                                try:
                                    snap_mounted_path = snap_mounted_path.replace("\\U", "\\u").decode('unicode_escape').encode('utf-8')
                                except Exception as ex:
                                    print("Failed to decode unicode in snap_mounted_path")
                                    print(str(ex))
                                    continue
                            backup_list.append(target_volume('Snapshot-' + snapshot_volume['timestamp'], snap_mounted_path))
                        except Exception as ex:
                            print('Error trying to mount snapshot - ' + str(ex))
                            print('mount_result was : ' + str(mount_result))

    return backup_list


def unmount_all_localsnapshots():
    verify_codesign(cmd_tmutil)
    return_code = subprocess.call([cmd_tmutil, 'unmountlocalsnapshots', '/'])
    if not return_code:
        return True
    else:
        sys.exit('Failed to unmount local snapshtos. Please retry to unmount manually.\ntmutil unmountlocalsnapshots /')


def get_script_dir():
    return os.path.dirname(os.path.abspath(sys.argv[0]))


def read_config(config_file='macosac.ini'):
    if py3_flag:  # Python 3.x
        config = configparser.ConfigParser()
    else:         # PYthon 2.x
        config = ConfigParser.ConfigParser()
    config_file_path = os.path.join(get_script_dir(), config_file)
    if os.path.exists(config_file_path):
        config.read(config_file_path)
    else:
        sys.exit('Config file does not exits: {}'.format(config_file_path))
    return config


def list_config_categories():
    config = read_config()
    category_list = []
    print('macOS Artifact Collector have been set categories below:')
    for category in config.sections():
        if not category.startswith('__'):
            category_list.append(category)

    category_list.sort()
    category_list.insert(0, 'all')
    print('\n'.join(map(str, category_list)))


# return a list of artifact files
def setup_artifact_files(vol_root_path, categories):
    config = read_config()
    artifact_files = []
    for section in config.sections():
        if (section in categories) or ('all' in categories):
            for k, v in config.items(section):
                if v[0] == '/':
                    v = v[1:]  # Remove leading / else os.path.join will ignore the following part!
                path_list = glob.glob(os.path.join(vol_root_path, v), recursive=True)
                if len(path_list) > 0:
                    artifact_files.extend(path_list)
                else:
                    dbg_print('Files not found or cannot access: {}'.format(os.path.join(vol_root_path, v)))

    return artifact_files


# verify code signature of external command file
def verify_codesign(cmd):
    return_code = subprocess.call(['/usr/bin/codesign', '--verify', cmd])
    if not return_code:
        return True
    else:
        sys.exit('Failed to verify code signature: {}'.format(cmd))


def copy_metadata(path_src, path_dst, symlink=False):
    # print('copystat')
    # shutil.copystat(path_src, path_dst)
    try:
        tmp_flags = 0x0
        if symlink:
            file_stat = os.lstat(path_src)
            dbg_print('lstat: {}'.format(file_stat))
            dbg_print('lchown: {} : {} : {}'.format(path_dst, file_stat.st_uid, file_stat.st_gid))
            os.lchown(path_dst, file_stat.st_uid, file_stat.st_gid)
            dbg_print('lchmod: {}'.format(file_stat.st_mode))
            os.lchmod(path_dst, file_stat.st_mode)
        else:
            file_stat = os.stat(path_src)
            dbg_print('stat: {}'.format(file_stat))
            dbg_print('chown: {} : {} : {}'.format(path_dst, file_stat.st_uid, file_stat.st_gid))
            os.chown(path_dst, file_stat.st_uid, file_stat.st_gid)
            dbg_print('copymode')
            shutil.copymode(path_src, path_dst)

        # Unfortunately, os.utime() of Python 2 does not have the "follow_symlinks" option, so I have no idea to modify atime and mtime of a symlink itself.
        # https://stackoverflow.com/questions/48068739/how-can-i-change-atime-and-mtime-of-a-symbolic-link-from-python
        dbg_print('utime')
        if py3_flag and symlink:
            os.utime(path_dst, (file_stat.st_atime, file_stat.st_mtime), follow_symlinks=False)
        else:
            os.utime(path_dst, (file_stat.st_atime, file_stat.st_mtime))

        if file_stat.st_flags & stat.SF_NOUNLINK:
            tmp_flags |= stat.SF_NOUNLINK
        if file_stat.st_flags & 0x80000:
            # 0x80000 means SF_RESTRICTED, but Python cannot recognize it.
            # https://github.com/pypa/virtualenv/issues/1173
            # https://bugs.python.org/issue32347
            tmp_flags |= 0x80000
        dbg_print('file_stat st_flags ^ tmp_flags: {} | {}'.format(hex(file_stat.st_flags), hex(tmp_flags)))
        if symlink:
            os.lchflags(path_dst, file_stat.st_flags ^ tmp_flags)
        else:
            os.chflags(path_dst, file_stat.st_flags ^ tmp_flags)

        extattr_src = xattr.xattr(path_src)
        extattr_src_items = dict(extattr_src.items())
        extattr_dst = xattr.xattr(path_dst)
        dbg_print('xattr src: {}'.format(extattr_src.items()))
        if 'com.apple.rootless' in extattr_src.keys():
            del extattr_src_items['com.apple.rootless']
        # dbg_print('xattr dst: {}'.format(extattr_dst.items()))
        dbg_print('xattr src: {}'.format(extattr_src_items))
        extattr_dst.update(extattr_src_items)
        return True
    except (IOError, OSError, shutil.Error) as err:
        # sys.exit('Error has been occurred in copy_metadata(): {}'.format(err))
        return False


def builtin_copy(outputdir, artifact_list, log_file, copy_symlinks=False):
    try:
        log_fp = open(log_file, 'w')
        for artifact_file in artifact_list:
            artifact_dirs = artifact_file.split('/')
            artifact_dirs[0] = '/'
            path_src = artifact_dirs[0]
            path_dst = outputdir
            for dir in artifact_dirs[1:]:
                path_src = os.path.join(path_src, dir)
                path_dst = os.path.join(path_dst, dir)
                if not os.path.exists(path_dst):
                    if copy_symlinks and os.path.islink(path_src):
                        dbg_print('copy symlink: {} -> {}'.format(path_src, path_dst))
                        linkto = os.readlink(path_src)
                        os.symlink(linkto, path_dst)
                        copy_metadata(path_src, path_dst, True)
                        log_line = datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f') + ' symlink ' + path_src
                    elif os.path.isdir(path_src):
                        dbg_print('mkdir: {}'.format(path_dst))
                        os.mkdir(path_dst)
                        copy_metadata(path_src, path_dst)
                        log_line = datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f') + ' dir ' + path_src
                    else:  # elif os.path.isfile(path_src):
                        dbg_print('copy file: {} -> {}'.format(path_src, path_dst))
                        outputfile = os.path.join(outputdir, artifact_file[1:])
                        shutil.copy(artifact_file, outputfile)
                        copy_metadata(path_src, path_dst)
                        log_line = datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f') + ' file ' + path_src
                    log_fp.write(log_line + '\n')
        log_fp.close()
        return 0
    except (IOError, OSError, shutil.Error) as err:
        sys.exit('Error has been occurred in builtin_copy(): {}'.format(err))


def copy_artifact_files(outputdir, artifact_list, use_builtincopy=False, source_path='/'):
    # deduplicate artifact_list
    artifact_list = list(set(artifact_list))
    # Make paths relative to remove "/Volumes/com.apple.TimeMachine.localsnapshots/Backups.backupdb/..../Macintosh HD - Data" from path
    if source_path != '/':
        root_path_len = len(source_path)
        if source_path.endswith('/'):
            root_path_len -= 1
        artifact_list = [x[0:root_path_len] + '/.' + x[root_path_len:] for x in artifact_list]
    log_file = os.path.join(outputdir, 'copy_artifact_files.log')
    if use_builtincopy:
        returncode = builtin_copy(outputdir, artifact_list, log_file)
    else:
        verify_codesign(cmd_rsync)
        temp_dir = tempfile.mkdtemp(dir=outputdir)
        rsync_opts = '-aREL'
        if dryrun_mode:
            rsync_opts = rsync_opts + 'n'
        if debug_mode:
            ps_rsync = subprocess.Popen([cmd_rsync, rsync_opts, '--progress', '--temp-dir=' + temp_dir, '--log-file=' + log_file, '--files-from=-', '/', outputdir], stdin=subprocess.PIPE)
        else:
            ps_rsync = subprocess.Popen([cmd_rsync, rsync_opts, '--temp-dir=' + temp_dir, '--log-file=' + log_file, '--files-from=-', '/', outputdir], stdin=subprocess.PIPE, stderr=subprocess.PIPE)

        if py3_flag:
            ps_rsync.communicate(input='\n'.join(artifact_list).encode('utf-8'))
        else:
            ps_rsync.communicate(input='\n'.join(artifact_list))
        shutil.rmtree(temp_dir)
        returncode = ps_rsync.returncode

    if not returncode:
        return True
    else:
        return False


# main
def main():
    global debug_mode
    global dryrun_mode
    global file_debug

    session_id = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    hostname = os.uname()[1].split('.')[0]
    host_and_session = hostname + '_' + session_id
    args = parse_arguments()

    debug_mode = args.debug
    dryrun_mode = args.dry_run

    if args.list:
        list_config_categories()
        sys.exit()

    if not debug_mode and os.getuid() != 0:
        sys.exit('This script needs root privilege.')

    if args.outputtype not in ['dir', 'dmg', 'ro-dmg']:
        sys.exit('outputtype option must be specified "dir", "dmg" or "ro-dmg".')

    if args.outputdir:
        base_outputdir = os.path.join(os.path.abspath(args.outputdir), host_and_session)
    else:
        base_outputdir = os.path.join(get_script_dir(), host_and_session)

    try:
        if args.outputtype == 'dir':
            print('Output dir: {}'.format(base_outputdir))
            os.makedirs(base_outputdir)
        elif args.outputtype == 'dmg' or args.outputtype == 'ro-dmg':
            pass
        else:
            sys.exit('Invalid output type: {}'.format(args.outputtype))

        if args.debug:
            file_debug = os.path.join(get_script_dir(), 'debug.log')
            print('Debug log: {}'.format(file_debug))
        print('')
    except Exception.FileExistsError:
        sys.exit('Unable to create output directory: {}'.format(base_outputdir))

    backup_target_list = list()
    if args.timemachine or args.localsnapshots:
        if args.timestamp:
            timestamp = args.timestamp

        if not args.volumename:
            volumename = determine_default_volume()
        else:
            volumename = args.volumename
        print('Target volume name: {}'.format(volumename))

        print('Detecting local snapshots and Time Machine backups...')
        backup_target_list = get_backup_targets(timestamp, args.timemachine, args.localsnapshots, volumename)
        print('{}'.format('\n'.join([x[1] for x in backup_target_list])))

    targets = [target_volume('ROOT', '/')]
    if len(backup_target_list) > 0:
        targets.extend(backup_target_list)

    for target_vol in targets:
        artifact_list = list()
        print('Finding artifact files in {} for backup...'.format(target_vol.root_path))
        artifact_list.extend(setup_artifact_files(target_vol.root_path, [x.lower() for x in args.categories.split(',')]))

        print('Retrieving artifact file stat...')
        if args.outputtype == 'dir':
            outputdir = base_outputdir if target_vol.root_path == '/' else base_outputdir + '_' + target_vol.name
            print('Output dir: {}'.format(outputdir))
            try:
                if not os.path.exists(outputdir):
                    os.makedirs(outputdir)
            except OSError as ex:
                print('Error, failed to create output dir: ' + str(ex))
            file_stat_list, total_size = retrieve_file_stat(outputdir, artifact_list, args.timezone)
        elif args.outputtype == 'dmg' or args.outputtype == 'ro-dmg':
            if target_vol.root_path == '/':
                outputdmg = base_outputdir + '.dmg'
                outputdir = os.path.join('/Volumes', host_and_session)
            else:
                outputdmg = base_outputdir + '_' + target_vol.name + '.dmg'
                outputdir = os.path.join('/Volumes', host_and_session + '_' + target_vol.name)
            dmgdir = '/'.join(outputdmg.split('/')[:-1])
            file_stat_list, total_size = retrieve_file_stat(dmgdir, artifact_list, args.timezone)

        print('Checking outputdir free space...')
        if args.outputtype == 'dir' and total_size * 1.05 >= os.statvfs(outputdir).f_bfree * os.statvfs(outputdir).f_frsize:
            sys.exit("{} doesn't have enough free space.".format(outputdir))
        elif args.outputtype == 'dmg' and total_size * 1.1 >= os.statvfs(dmgdir).f_bfree * os.statvfs(dmgdir).f_frsize:
            sys.exit("{} doesn't have enough free space.".format(dmgdir))
        elif args.outputtype == 'ro-dmg' and (total_size * 1.1) * 2 >= os.statvfs(dmgdir).f_bfree * os.statvfs(dmgdir).f_frsize:
            sys.exit("{} doesn't have enough free space.".format(dmgdir))

        if args.outputtype == 'dmg' or args.outputtype == 'ro-dmg':
            print('Creating and mounting DMG file...')
            if target_vol.root_path == '/':
                vol_name = host_and_session
            else:
                vol_name = host_and_session + '_' + target_vol.name
                outputdmg = base_outputdir + '_' + target_vol.name + '.dmg'
            create_and_mount_dmg(outputdmg, vol_name, total_size)
            print('Writing .fseventsd/no_log empty file...')
            write_no_log_fseventsd_file(outputdir)

        print('Saving file stat...')
        save_file_stat(outputdir, file_stat_list)

        print('Copying artifact files...')
        copy_artifact_files(outputdir, artifact_list, args.use_builtincopy, target_vol.root_path)

        if args.outputtype == 'dmg' or args.outputtype == 'ro-dmg':
            print('Unmounting DMG file...')
            unmount_dmg(vol_name)

            if args.outputtype == 'ro-dmg':
                print('Converting DMG file to Read Only DMG file...')
                convert_dmg(outputdmg)

    if args.localsnapshots:
        print('Unmounting all local snapshots...')
        unmount_all_localsnapshots()

    print('Finished.')
    print('\nNote that the copied files have the same meta information (e.g. permission, extended attributes, or etc.) as their original files.\n')


if __name__ == "__main__":
    main()
