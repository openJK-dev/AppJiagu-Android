# ApkSteady

#### 介绍
Android. APK加固。该项目包含了对加固后的apk进行dex解密和加载

## 一、生成 Shell.aar(dex 解密和类加载)

### 1、解密加固的 dex 文件的流程
1. 在 Application 中可以通过 getApplicationInfo().sourceDir 来获取 base APK，这个 apk 就包含了我们应用的所有代码。
2. 通过 Application 的getDir() 方法，我们在应用的私有目录创建一个私有文件夹 SteadyDir
3. 在 2 中创建的目录里面我们将 bask.apk 解压
4. 解压后我们得到 apk 的所有文件，然后过滤出所有以dex为后缀的文件。其中 classes.dex 文件我们不需要因为它已经被加载进系统，所以只需要处理被我们加密的dex 文件
5. 将解密后的 dex 文件加载到程序中
6. 运行 apk 真实的 application，启动 app

### 2、如何解压 apk 文件

zip 解压主要用到了 java 中的 ZipFile 类，具体实现直接上代码，代码中包含注释就不多解释。

```java
public static void unZip(File zip, File dir) {
    try {
        //清空存放解压文件的目录
        deleteFile(dir);
        ZipFile zipFile = new ZipFile(zip);
        //zip文件中每一个条目
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        //遍历
        while (entries.hasMoreElements()) {
            ZipEntry zipEntry = entries.nextElement();
            //zip中 文件/目录名
            String name = zipEntry.getName();
            //原来的签名文件 不需要了
            if (name.equals("META-INF/CERT.RSA") || name.equals("META-INF/CERT.SF") || name
                    .equals("META-INF/MANIFEST.MF")) {
                continue;
            }
            //空目录不管
            if (!zipEntry.isDirectory()) {
                File file = new File(dir, name);
                //创建目录
                if (!file.getParentFile().exists()) {
                    file.getParentFile().mkdirs();
                }
                //写文件
                FileOutputStream fos = new FileOutputStream(file);
                InputStream is = zipFile.getInputStream(zipEntry);
                byte[] buffer = new byte[2048];
                int len;
                while ((len = is.read(buffer)) != -1) {
                    fos.write(buffer, 0, len);
                }
                is.close();
                fos.close();
            }
        }
        zipFile.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}


private static void deleteFile(File file){
    if (file.isDirectory()){
        File[] files = file.listFiles();
        for (File f: files) {
            deleteFile(f);
        }
    }else{
        file.delete();
    }
}
```

### 3、如何解密 dex 文件

通过第二步中的解压方式，我们可以很轻松的将 base.apk 解压到私有目录下。然后我们通过文件的后缀名.dex 过滤出所有 dex 文件（排除 classes.dex），接着读取每个  dex 到字节数组中，然后对字节数组进行解密操作。
这里加解密使用的是 AES 的方式，为了增加安全性这里将解密的方式用 jni 方式完成。解密方式如下：

```c++
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
```

### 4、加载 dex 文件
通过上面的解压和解密操作我们得到了原始的 dex 文件，我们将这些dex文件放进一个集合中,接下来使用类加载机制加载已经解密后的 dex 文件。关于类加载机制会在后续文章中讲解。
```java
public static void loadDex(Application application,List<File> dexFiles, File versionDir) throws Exception{
    //1.先从 ClassLoader 中获取 pathList 的变量
    Field pathListField = ProxyUtils.findField(application.getClassLoader(), "pathList");
    //1.1 得到 DexPathList 类
    Object pathList = pathListField.get(application.getClassLoader());
    //1.2 从 DexPathList 类中拿到 dexElements 变量
    Field dexElementsField= ProxyUtils.findField(pathList,"dexElements");
    //1.3 拿到已加载的 dex 数组
    Object[] dexElements=(Object[])dexElementsField.get(pathList);

    //2. 反射到初始化 dexElements 的方法，也就是得到加载 dex 到系统的方法
    Method makeDexElements= ProxyUtils.findMethod(pathList,"makePathElements",List.class,File.class,List.class);
    //2.1 实例化一个 集合  makePathElements 需要用到
    ArrayList<IOException> suppressedExceptions = new ArrayList<IOException>();
    //2.2 反射执行 makePathElements 函数，把已解码的 dex 加载到系统，不然是打不开 dex 的，会导致 crash
    Object[] addElements=(Object[])makeDexElements.invoke(pathList,dexFiles,versionDir,suppressedExceptions);

    //3. 实例化一个新数组，用于将当前加载和已加载的 dex 合并成一个新的数组
    Object[] newElements= (Object[]) Array.newInstance(dexElements.getClass().getComponentType(),dexElements.length+addElements.length);
    //3.1 将系统中的已经加载的 dex 放入 newElements 中
    System.arraycopy(dexElements,0,newElements,0,dexElements.length);
    //3.2 将解密后已加载的 dex 放入新数组中
    System.arraycopy(addElements,0,newElements,dexElements.length,addElements.length);

    //4. 将合并的新数组重新设置给 DexPathList的 dexElements
    dexElementsField.set(pathList,newElements);
}
```
### 5、加载真实的 application 类，运行 app
1、首先从 AndroidManifest.xml 文件中获取到原 application 的类名。（在下一篇文章中会讲解我们如何将 apk 的原来的 application 类名放到 AndroidManifest.xml 的meta-data 标签下）
```java
/**
 * 解析项目中原来的 Application 名称
 */
private void getMateData(){
    try{
        ApplicationInfo applicationInfo = getPackageManager().getApplicationInfo(getPackageName(),
                PackageManager.GET_META_DATA);//获取包信息
        Bundle metaData = applicationInfo.metaData;//获取 Meta-data 的键值对信息
        if(null != metaData){
            if(metaData.containsKey("app_name")){
                app_name = metaData.getString("app_name");//获取原来的包名
            }
        }
    }catch (Exception e){
        e.printStackTrace();
    }
}
```
2、获取到原 application 的类名后就通过反射获取到 application 的实例。
```
private void bindRealApplication() throws Exception{
        if(isBindReal){
            return;
        }
        if(TextUtils.isEmpty(app_name)){
            return;
        }
        //1、得到 attachBaseContext(context)传入的上下文 ContextImpl
        Context baseContext = getBaseContext();
        //2、拿到真实 APK Application 的 class
        Class<?> delegateClass = Class.forName(app_name);
        //反射实例化，
        delegate = (Application) delegateClass.newInstance();
        //得到 Application attach() 方法 也就是最先初始化的
        Method attach = Application.class.getDeclaredMethod("attach",Context.class);
        attach.setAccessible(true);
        //执行 Application#attach(Context)
        attach.invoke(delegate,baseContext);

        //        ContextImpl---->mOuterContext(app)   通过Application的attachBaseContext回调参数获取
        //4. 拿到 Context 的实现类
        Class<?> contextImplClass = Class.forName("android.app.ContextImpl");
        //4.1 获取 mOuterContext Context 属性
        Field mOuterContextField = contextImplClass.getDeclaredField("mOuterContext");
        mOuterContextField.setAccessible(true);
        //4.2 将真实的 Application 交于 Context 中。这个根据源码执行，实例化 Application 下一个就行调用 setOuterContext 函数，所以需要绑定 Context
        //  app = mActivityThread.mInstrumentation.newApplication(
        //                    cl, appClass, appContext);
        //  appContext.setOuterContext(app);
        mOuterContextField.set(baseContext, delegate);

//        ActivityThread--->mAllApplications(ArrayList)       ContextImpl的mMainThread属性
        //5. 拿到 ActivityThread 变量
        Field mMainThreadField = contextImplClass.getDeclaredField("mMainThread");
        mMainThreadField.setAccessible(true);
        //5.1 拿到 ActivityThread 对象
        Object mMainThread = mMainThreadField.get(baseContext);

//        ActivityThread--->>mInitialApplication
        //6. 反射拿到 ActivityThread class
        Class<?> activityThreadClass=Class.forName("android.app.ActivityThread");
        //6.1 得到当前加载的 Application 类
        Field mInitialApplicationField = activityThreadClass.getDeclaredField("mInitialApplication");
        mInitialApplicationField.setAccessible(true);
        //6.2 将 ActivityThread 中的 Applicaiton 替换为 真实的 Application 可以用于接收相应的声明周期和一些调用等
        mInitialApplicationField.set(mMainThread,delegate);


//        ActivityThread--->mAllApplications(ArrayList)       ContextImpl的mMainThread属性
        //7. 拿到 ActivityThread 中所有的 Application 集合对象，这里是多进程的场景
        Field mAllApplicationsField = activityThreadClass.getDeclaredField("mAllApplications");
        mAllApplicationsField.setAccessible(true);
        ArrayList<Application> mAllApplications =(ArrayList<Application>) mAllApplicationsField.get(mMainThread);
        //7.1 删除 ProxyApplication
        mAllApplications.remove(this);
        //7.2 添加真实的 Application
        mAllApplications.add(delegate);

//        LoadedApk------->mApplication                      ContextImpl的mPackageInfo属性
        //8. 从 ContextImpl 拿到 mPackageInfo 变量
        Field mPackageInfoField = contextImplClass.getDeclaredField("mPackageInfo");
        mPackageInfoField.setAccessible(true);
        //8.1 拿到 LoadedApk 对象
        Object mPackageInfo=mPackageInfoField.get(baseContext);

        //9 反射得到 LoadedApk 对象
        //    @Override
        //    public Context getApplicationContext() {
        //        return (mPackageInfo != null) ?
        //                mPackageInfo.getApplication() : mMainThread.getApplication();
        //    }
        Class<?> loadedApkClass=Class.forName("android.app.LoadedApk");
        Field mApplicationField = loadedApkClass.getDeclaredField("mApplication");
        mApplicationField.setAccessible(true);
        //9.1 将 LoadedApk 中的 Application 替换为 真实的 Application
        mApplicationField.set(mPackageInfo,delegate);

        //修改ApplicationInfo className   LooadedApk

        //10. 拿到 LoadApk 中的 mApplicationInfo 变量
        Field mApplicationInfoField = loadedApkClass.getDeclaredField("mApplicationInfo");
        mApplicationInfoField.setAccessible(true);
        //10.1 根据变量反射得到 ApplicationInfo 对象
        ApplicationInfo mApplicationInfo = (ApplicationInfo)mApplicationInfoField.get(mPackageInfo);
        //10.2 将我们真实的 APPlication ClassName 名称赋值于它
        mApplicationInfo.className=app_name;

        //11. 执行 代理 Application onCreate 声明周期
        delegate.onCreate();

        //解码完成
        isBindReal = true;

    }
```
至此 apk 的解密便结束了

#### 参与贡献

1.  Fork 本仓库
2.  新建 Feat_xxx 分支
3.  提交代码
4.  新建 Pull Request


#### 特技

1.  使用 Readme\_XXX.md 来支持不同的语言，例如 Readme\_en.md, Readme\_zh.md
2.  Gitee 官方博客 [blog.gitee.com](https://blog.gitee.com)
3.  你可以 [https://gitee.com/explore](https://gitee.com/explore) 这个地址来了解 Gitee 上的优秀开源项目
4.  [GVP](https://gitee.com/gvp) 全称是 Gitee 最有价值开源项目，是综合评定出的优秀开源项目
5.  Gitee 官方提供的使用手册 [https://gitee.com/help](https://gitee.com/help)
6.  Gitee 封面人物是一档用来展示 Gitee 会员风采的栏目 [https://gitee.com/gitee-stars/](https://gitee.com/gitee-stars/)
