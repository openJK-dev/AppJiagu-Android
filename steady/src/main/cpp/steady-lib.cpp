#include <jni.h>
#include <string>
#include <android/log.h>

#define TAG "steady-jni"
// 定义debug信息
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,TAG,__VA_ARGS__)
// 定义error信息
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,TAG,__VA_ARGS__)
// 定义info信息
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,TAG,__VA_ARGS__)

jbyteArray readClassesDexFromApk(JNIEnv *pEnv, jobject pJobject);

void
extraTargetZipFileFromDex(JNIEnv *env, jobject obj, jstring fileName, jbyteArray classesDexData);

jbyteArray decrypt(JNIEnv *env,jbyteArray srcData);

extern "C" JNIEXPORT jstring JNICALL
Java_com_sakuqi_apksteady_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

jbyteArray decrypt(JNIEnv *env,jbyteArray srcData) {
    jstring type = (*env).NewStringUTF("AES");
    jstring cipher_mode = (*env).NewStringUTF("AES/ECB/PKCS5Padding");
    jbyteArray pwd = (*env).NewByteArray(16);
    char *master_key = (char *) "huangdh'l,.AMWK;";
    (*env).SetByteArrayRegion(pwd,0,16,reinterpret_cast<jbyte *>(master_key));

    jclass secretKeySpecClass = (*env).FindClass("javax/crypto/spec/SecretKeySpec");
    jmethodID secretKeySpecMethodId = (*env).GetMethodID(secretKeySpecClass,"<init>", "([BLjava/lang/String;)V");
    jobject secretKeySpecObj = (*env).NewObject(secretKeySpecClass,secretKeySpecMethodId,pwd,type);

    jclass cipherClass = (*env).FindClass("javax/crypto/Cipher");
    jmethodID cipherInitMethodId = (*env).GetMethodID(cipherClass,"init", "(ILjava/security/Key;)V");
    jmethodID cipherInstanceMethodId = (*env).GetStaticMethodID(cipherClass,"getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;");
    jobject cipherObj = (*env).CallStaticObjectMethod(cipherClass,cipherInstanceMethodId,cipher_mode);

    jfieldID decryptModeFieldId = (*env).GetStaticFieldID(cipherClass,"DECRYPT_MODE", "I");
    jint mode = (*env).GetStaticIntField(cipherClass,decryptModeFieldId);
    (*env).CallVoidMethod(cipherObj,cipherInitMethodId,mode,secretKeySpecObj);

    jmethodID doFinalMethodId = (*env).GetMethodID(cipherClass,"doFinal", "([B)[B");
    jbyteArray text = (jbyteArray)(*env).CallObjectMethod(cipherObj,doFinalMethodId,srcData);
    return text;
}

jbyteArray readClassesDexFromApk(JNIEnv *env, jobject obj) {
    jclass byteArryOutputStreamClass = (*env).FindClass("java/io/ByteArrayOutputStream");
    jmethodID byteArrayOutputStreamMethodID = (*env).GetMethodID(byteArryOutputStreamClass,"<init>","()V");
    jmethodID writeMethodId = (*env).GetMethodID(byteArryOutputStreamClass,"write","([BII)V");
    jmethodID toByteArrayMethodId = (*env).GetMethodID(byteArryOutputStreamClass,"toByteArray","()[B");
    jobject byteArrayOutputStreamObj = (*env).NewObject(byteArryOutputStreamClass,byteArrayOutputStreamMethodID);
    jclass applicationClass = (*env).GetObjectClass(obj);
    jmethodID getApplicationInfoMethodId = (*env).GetMethodID(applicationClass,"getApplicationInfo","()Landroid/content/pm/ApplicationInfo;");
    jobject applicationInfoObj = (*env) . CallObjectMethod(obj,getApplicationInfoMethodId);

    jclass applicationInfoClass = (*env).GetObjectClass(applicationInfoObj);
    jfieldID sourceDirFieldId = (*env).GetFieldID(applicationInfoClass,"sourceDir","Ljava/lang/String;");
    jstring sourceDirString = (jstring)(*env).GetObjectField(applicationInfoObj,sourceDirFieldId);
    const char* str = (*env).GetStringUTFChars(sourceDirString,0);

    jclass fileInputStreamClass = (*env).FindClass("java/io/FileInputStream");
    jmethodID fileInputStreamMethodId = (*env).GetMethodID(fileInputStreamClass,"<init>","(Ljava/lang/String;)V");
    jobject fileInputStreamObj = (*env).NewObject(fileInputStreamClass,fileInputStreamMethodId,sourceDirString);

    jclass bufferedInputStreamClass = (*env).FindClass("java/io/BufferedInputStream");
    jmethodID  bufferedInputStreamMethodId = (*env).GetMethodID(bufferedInputStreamClass,"<init>","(Ljava/io/InputStream;)V");
    jobject bufferedInputStreamObj = (*env).NewObject(bufferedInputStreamClass,bufferedInputStreamMethodId,fileInputStreamObj);

    jclass zipInputStreamClass = (*env).FindClass("java/util/zip/ZipInputStream");
    jmethodID zipInputStreamMethodID = (*env).GetMethodID(zipInputStreamClass,"<init>","(Ljava/io/InputStream;)V");
    jobject zipInputStreamObj = (*env).NewObject(zipInputStreamClass,zipInputStreamMethodID,bufferedInputStreamObj);

    jmethodID closeMethodId = (*env).GetMethodID(zipInputStreamClass,"close","()V");
    jmethodID readMethodId = (*env).GetMethodID(zipInputStreamClass,"read","([B)I");
    jmethodID getNextEntryMethodID = (*env).GetMethodID(zipInputStreamClass,"getNextEntry","()Ljava/util/zip/ZipEntry;");
    jmethodID closeEntryMethodID = (*env).GetMethodID(zipInputStreamClass,"closeEntry","()V");

    jclass zipEntryClass = (*env).FindClass("java/util/zip/ZipEntry");
    jmethodID  getNameMethodId = (*env).GetMethodID(zipEntryClass,"getName","()Ljava/lang/String;");
    while (1){
        jobject zipEntryObj = (*env).CallObjectMethod(zipInputStreamObj,getNextEntryMethodID);
        if(zipEntryObj == NULL){
            (*env).CallVoidMethod(zipInputStreamObj,closeMethodId);
            break;
        }
        jstring entryName = (jstring)(*env).CallObjectMethod(zipEntryObj,getNameMethodId);
        const char* entryNameStr = (*env).GetStringUTFChars(entryName,0);
        if(strcmp(entryNameStr,"classes.dex") == 0){
            jbyteArray buffer = (*env).NewByteArray(1024);
            while (1){
                int ret = (*env).CallIntMethod(zipInputStreamObj,readMethodId,buffer);
                if(-1 == ret){
                    break;
                }
                (*env).CallVoidMethod(byteArrayOutputStreamObj,writeMethodId,buffer,0,ret);
            }
            (*env).ReleaseStringUTFChars(entryName,entryNameStr);
            (*env).CallVoidMethod(zipInputStreamObj,closeEntryMethodID);
            break;
        }
        (*env).ReleaseStringUTFChars(entryName,entryNameStr);
        (*env).DeleteLocalRef(entryName);
        (*env).DeleteLocalRef(zipEntryObj);
        (*env).CallVoidMethod(zipInputStreamObj,closeEntryMethodID);
    }
    (*env).CallVoidMethod(zipInputStreamObj,closeMethodId);
    (*env).ReleaseStringUTFChars(sourceDirString,str);

    jbyteArray retArray = (jbyteArray)(*env).CallObjectMethod(byteArrayOutputStreamObj,toByteArrayMethodId);
    return retArray;
}

void extraTargetZipFileFromDex(JNIEnv *env, jobject obj,jbyteArray classesDexData, jstring targetFileName) {
    jsize dexLen = (*env).GetArrayLength(classesDexData);
    jbyteArray targetZipLenArray = (*env).NewByteArray(4);
    jclass systemClass = (*env).FindClass("java/lang/System");
    jmethodID  arrayCopyMethodId = (*env).GetStaticMethodID(systemClass,"arraycopy", "(Ljava/lang/Object;ILjava/lang/Object;II)V");
    (*env).CallStaticVoidMethod(systemClass,arrayCopyMethodId,classesDexData,dexLen-4,targetZipLenArray,0,4);

    jclass baisClass = (*env).FindClass("java/io/ByteArrayInputStream");
    jmethodID baisMethodId = (*env).GetMethodID(baisClass,"<init>", "([B)V");
    jobject bsisObj = (*env).NewObject(baisClass,baisMethodId,targetZipLenArray);

    jclass dataInputStreamClass = (*env).FindClass("java/io/DataInputStream");
    jmethodID  dataInputStreamMethodID = (*env).GetMethodID(dataInputStreamClass,"<init>", "(Ljava/io/InputStream;)V");
    jmethodID readIntMethodId = (*env).GetMethodID(dataInputStreamClass,"readLong", "()J");
    jobject dataInputStreamObj = (*env).NewObject(dataInputStreamClass,dataInputStreamMethodID,bsisObj);
    long targetZipLen = (*env).CallLongMethod(dataInputStreamObj,readIntMethodId);

    jbyteArray targetZipData = (*env).NewByteArray(targetZipLen);
    (*env).CallStaticVoidMethod(systemClass,arrayCopyMethodId,classesDexData,dexLen-targetZipLen-4,targetZipData,0,targetZipLen);

    jbyteArray decodedTargetZipData = decrypt(env,targetZipData);
    jclass fileClass = (*env).FindClass("java/io/File");
    jmethodID  fileMethodId = (*env).GetMethodID(fileClass,"<init>", "(Ljava/lang/String;)V");
    jobject fileObj = (*env).NewObject(fileClass,fileMethodId,targetFileName);

    jclass fileOutputStreamClass = (*env).FindClass("java/io/FileOutputStream");
    jmethodID fileOutputStreamMethodId = (*env).GetMethodID(fileOutputStreamClass,"<init>", "(Ljava/io/File;)V");
    jmethodID fos_write_methodId = (*env).GetMethodID(fileOutputStreamClass,"write", "([B)V");
    jmethodID fos_flush_methodId = (*env).GetMethodID(fileOutputStreamClass,"flush","()V");
    jmethodID fos_close_methodId = (*env).GetMethodID(fileOutputStreamClass,"close", "()V");

    jobject fileOutputStreamObj = (*env).NewObject(fileOutputStreamClass,fileOutputStreamMethodId,fileObj);
    (*env).CallVoidMethod(fileOutputStreamObj,fos_write_methodId,decodedTargetZipData);
    (*env).CallVoidMethod(fileOutputStreamObj,fos_flush_methodId);
    (*env).CallVoidMethod(fileOutputStreamObj,fos_close_methodId);

}


extern "C"
JNIEXPORT void JNICALL
Java_com_sakuqi_steady_SteadyApplication_unsteady(JNIEnv *env, jobject obj, jstring apk_file,
                                                  jobject application) {
    //创建一个解压 APK 的内部目录
    jclass contextWrapperClass = (*env) . FindClass("android/content/ContextWrapper");
    jmethodID  getDirMethodId = (*env).GetMethodID(contextWrapperClass,"getDir","(Ljava/lang/String;I)Ljava/io/File;");
    jstring path_name = (*env).NewStringUTF("steady");
    jclass contextClass = (*env).FindClass("android/content/Context");
    jfieldID  fid = (*env) . GetStaticFieldID(contextClass,"MODE_PRIVATE","I");
    jint i = (*env).GetStaticIntField(contextClass,fid);
    jobject fileDir = (*env).CallObjectMethod(application,getDirMethodId,path_name,i);

    jclass fileClass = (*env) .FindClass("java/io/File");
    jmethodID  getAbsolutePath_methodID = (*env).GetMethodID(fileClass,"getAbsolutePath","()Ljava/lang/String;");
    jstring odexPath = (jstring)(*env).CallObjectMethod(fileDir,getAbsolutePath_methodID);
    const char *path = env -> GetStringUTFChars(odexPath,0);
    LOGD("odexPath=%s",path);
    jclass stringBufferClass = (*env).FindClass("java/lang/StringBuffer");
    jmethodID initStringBufferMethod = (*env).GetMethodID(stringBufferClass,"<init>","()V");
    jobject stringBufferObj = (*env).NewObject(stringBufferClass,initStringBufferMethod);
    jmethodID  append_methodId = (*env).GetMethodID(stringBufferClass,"append","(Ljava/lang/String;)Ljava/lang/StringBuffer;");

    (*env) . CallObjectMethod(stringBufferObj,append_methodId,odexPath);
    jstring zip_str = (*env).NewStringUTF("/TargetApk.zip");
    (*env).CallObjectMethod(stringBufferObj,append_methodId,zip_str);

    jmethodID toString_methodId = (*env).GetMethodID(stringBufferClass,"toString","()Ljava/lang/String;");
    jstring targetFileName = (jstring)(*env).CallObjectMethod(stringBufferObj,toString_methodId);

    jmethodID  initFile_methodId = (*env).GetMethodID(fileClass,"<init>","(Ljava/lang/String;)V");
    jobject targetApkZipFileObj = (*env).NewObject(fileClass,initFile_methodId,targetFileName);

    jmethodID  createNewFile_methodID = (*env).GetMethodID(fileClass,"createNewFile","()Z");
    (*env).CallBooleanMethod(targetApkZipFileObj,createNewFile_methodID);

    jbyteArray classesDexData = readClassesDexFromApk(env,obj);
    extraTargetZipFileFromDex(env,obj,classesDexData,targetFileName);

}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_sakuqi_steady_SteadyApplication_decrypt(JNIEnv *env, jobject thiz, jbyteArray data) {
    jbyteArray text = decrypt(env,data);
    return text;
}