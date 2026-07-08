import * as path from 'path';

const VENDOR_FOLDER = '.vscode';

export const EXTENSION_NAME = 'sftpEnhanced';
export const EXTENSION_DISPLAY_NAME = 'SFTP Enhanced';
export const SETTING_KEY_REMOTE = 'remotefs.remote';

export const REMOTE_SCHEME = 'remote';

export const CONGIF_FILENAME = 'sftp.json';
export const CONFIG_PATH = path.join(VENDOR_FOLDER, CONGIF_FILENAME);

// command not in package.json
export const COMMAND_TOGGLE_OUTPUT = 'sftpEnhanced.toggleOutput';

// commands in package.json
export const COMMAND_CONFIG = 'sftpEnhanced.config';
export const COMMAND_SET_PROFILE = 'sftpEnhanced.setProfile';
export const COMMAND_CANCEL_ALL_TRANSFER = 'sftpEnhanced.cancelAllTransfer';
export const COMMAND_OPEN_CONNECTION_IN_TERMINAL = 'sftpEnhanced.openConnectInTerminal';

export const COMMAND_FORCE_UPLOAD = 'sftpEnhanced.forceUpload';
export const COMMAND_UPLOAD = 'sftpEnhanced.upload';
export const COMMAND_UPLOAD_FILE = 'sftpEnhanced.upload.file';
export const COMMAND_UPLOAD_CHANGEDFILES = 'sftpEnhanced.upload.changedFiles';
export const COMMAND_UPLOAD_ACTIVEFILE = 'sftpEnhanced.upload.activeFile';
export const COMMAND_UPLOAD_FOLDER = 'sftpEnhanced.upload.folder';
export const COMMAND_UPLOAD_ACTIVEFOLDER = 'sftpEnhanced.upload.activeFolder';
export const COMMAND_UPLOAD_PROJECT = 'sftpEnhanced.upload.project';

export const COMMAND_FORCE_UPLOAD_TO_ALL_PROFILES = 'sftpEnhanced.forceUpload.to.allProfiles';
export const COMMAND_UPLOAD_TO_ALL_PROFILES = 'sftpEnhanced.upload.to.allProfiles';
export const COMMAND_UPLOAD_FILE_TO_ALL_PROFILES = 'sftpEnhanced.upload.file.to.allProfiles';
export const COMMAND_UPLOAD_ACTIVEFILE_TO_ALL_PROFILES = 'sftpEnhanced.upload.activeFile.to.allProfiles';
export const COMMAND_UPLOAD_FOLDER_TO_ALL_PROFILES = 'sftpEnhanced.upload.folder.to.allProfiles';
export const COMMAND_UPLOAD_ACTIVEFOLDER_TO_ALL_PROFILES = 'sftpEnhanced.upload.activeFolder.to.allProfiles';
export const COMMAND_UPLOAD_PROJECT_TO_ALL_PROFILES = 'sftpEnhanced.upload.project.to.allProfiles';

export const COMMAND_FORCE_DOWNLOAD = 'sftpEnhanced.forceDownload';
export const COMMAND_DOWNLOAD = 'sftpEnhanced.download';
export const COMMAND_DOWNLOAD_FILE = 'sftpEnhanced.download.file';
export const COMMAND_DOWNLOAD_ACTIVEFILE = 'sftpEnhanced.download.activeFile';
export const COMMAND_DOWNLOAD_FOLDER = 'sftpEnhanced.download.folder';
export const COMMAND_DOWNLOAD_ACTIVEFOLDER = 'sftpEnhanced.download.activeFolder';
export const COMMAND_DOWNLOAD_PROJECT = 'sftpEnhanced.download.project';

export const COMMAND_SYNC_LOCAL_TO_REMOTE = 'sftpEnhanced.sync.localToRemote';
export const COMMAND_SYNC_REMOTE_TO_LOCAL = 'sftpEnhanced.sync.remoteToLocal';
export const COMMAND_SYNC_BOTH_DIRECTIONS = 'sftpEnhanced.sync.bothDirections';

export const COMMAND_DIFF = 'sftpEnhanced.diff';
export const COMMAND_DIFF_ACTIVEFILE = 'sftpEnhanced.diff.activeFile';
export const COMMAND_LIST = 'sftpEnhanced.list';
export const COMMAND_LIST_ACTIVEFOLDER = 'sftpEnhanced.listActiveFolder';
export const COMMAND_LIST_ALL = 'sftpEnhanced.listAll';
export const COMMAND_DELETE_REMOTE = 'sftpEnhanced.delete.remote';
export const COMMAND_REVEAL_IN_EXPLORER = 'sftpEnhanced.revealInExplorer';
export const COMMAND_REVEAL_IN_REMOTE_EXPLORER = 'sftpEnhanced.revealInRemoteExplorer';

export const COMMAND_REMOTEEXPLORER_REFRESH = 'sftpEnhanced.remoteExplorer.refresh';
export const COMMAND_REMOTEEXPLORER_EDITINLOCAL = 'sftpEnhanced.remoteExplorer.editInLocal';
export const COMMAND_REMOTEEXPLORER_VIEW_CONTENT = 'sftpEnhanced.viewContent';

export const COMMAND_CREATE_FOLDER = 'sftpEnhanced.create.folder';
export const COMMAND_CREATE_FILE = 'sftpEnhanced.create.file';
