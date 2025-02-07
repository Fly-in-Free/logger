package com.arover.app.logger;

import android.os.Handler;

import com.arover.app.util.IoUtil;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * log file compress thread.
 */
class LogCompressor implements Runnable {
    private static final String TAG = "LogCompressor";
    private static final int BUFFER_SIZE = 4096;
    private final Handler logThreadHandler;
    private final String logFolder;
    private final String currentWritingLogFile;

    public LogCompressor(Handler handler, String dir, String currentLogFileName) {
        logThreadHandler = handler;
        logFolder = dir;
        currentWritingLogFile = currentLogFileName;
    }

    @Override
    public void run() {
        try {
            FileFilter logFilter = pathname -> pathname.getName().endsWith(".log");

            File[] logFiles = new File(logFolder).listFiles(logFilter);

            if(logFiles == null){
                Log.v(TAG,"no logs");
                return;
            }

            for (File logFile : logFiles) {

                if (logFile.getName().endsWith(currentWritingLogFile)) {
                    Log.v(TAG, "skip current log file=" + logFile.getName());
                    continue;
                }

                Log.d(TAG, "found log file=" + logFile.getName() +" compressing...");

                zipFile(logFile.getName(), logFile.getName().replaceFirst("\\.log", ".zip"));

                if (!logFile.delete()) {
                    Log.w(TAG, "failed to delete old log:" + logFile.getName());
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "findAllOldLogsAndCompress:" + e.getMessage(), e);
        }

        Log.d(TAG, "findAllOldLogsAndCompress: logThreadHandler is null? " + (logThreadHandler == null));
        if (logThreadHandler != null) {
            logThreadHandler.sendEmptyMessage(LogWriterThread.MSG_COMPRESS_COMPLETED);
        }
    }

    private void zipFile(String filename, String zipFileName) {
        Log.d(TAG, "zip filename:" + filename + ",zip file name:" + zipFileName);
        FileOutputStream dest = null;
        ZipOutputStream out = null;
        FileInputStream fi = null;
        BufferedInputStream origin = null;
        try {
            dest = new FileOutputStream(logFolder + File.separator + zipFileName);
            out = new ZipOutputStream(new BufferedOutputStream(dest));
            byte[] data = new byte[BUFFER_SIZE];

            fi = new FileInputStream(logFolder + File.separator + filename);
            origin = new BufferedInputStream(fi, BUFFER_SIZE);

            ZipEntry entry = new ZipEntry(filename.substring(filename.lastIndexOf("/") + 1));
            out.putNextEntry(entry);
            int count;

            while ((count = origin.read(data, 0, BUFFER_SIZE)) != -1) {
                out.write(data, 0, count);
            }
            out.closeEntry();
        } catch (Exception e) {
            Log.e(TAG, "zip error:", e);
        } finally {
            IoUtil.closeQuietly(fi);
            IoUtil.closeQuietly(origin);
            IoUtil.closeQuietly(out);
            IoUtil.closeQuietly(dest);
        }
    }
}
