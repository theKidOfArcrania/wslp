# anon-overlayfs

This is a user-mode file system that performs an anonymous CoW overlay of a
single file. We use this to overlay over the VHDX file so that we do not have to
copy the file every single time (to conserve space and time).
