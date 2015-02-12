/*
 * (C) Copyright 2015 Dennis Titze
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * Contributors:
 *     Dennis Titze (https://github.com/titze)
 */
package com.example.library;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import android.annotation.SuppressLint;
import android.app.Application;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager.NameNotFoundException;
import android.util.Log;
import android.widget.Toast;
import dalvik.system.PathClassLoader;

/**
 * Library class which offers the test()-function to be called from other apps.
 * 
 * This function performs its task only if the caller verifies the library correctly.
 * 
 * @author titze
 *
 */
public class Library {
	// Tag for log output
	public static String TAG = "LIBRARY";

	/**
	 * get the Context of the Caller with hidden APIs
	 * @return the context Application
	 */
	private static Application getContext() {
		try {
			final Class<?> activityThreadClass = Class.forName("android.app.ActivityThread");
			final Method method = activityThreadClass.getMethod("currentApplication");
			return (Application) method.invoke(null, (Object[]) null);
		} catch (final ClassNotFoundException e) {
			// handle exception
		} catch (final NoSuchMethodException e) {
			// handle exception
		} catch (final IllegalArgumentException e) {
			// handle exception
		} catch (final IllegalAccessException e) {
			// handle exception
		} catch (final InvocationTargetException e) {
			// handle exception
		}
		return null;
	}

	/**
	 * get the name of the app this code is executed from.
	 * We can not only check the calling class package name, since both the app name and the package name can be arbitrary.
	 * 
	 * @return the package name of the app that is currently executing the code. If another app calls this library, this is the app's package name
	 */
	private static String getCallingAppName() {
		String appName = null;

		try {
			int id = android.os.Process.myPid();
			String line;
			//			Slower Alternative:
			//			StringBuffer sb = new StringBuffer();
			//			Process p = Runtime.getRuntime().exec("cat /proc/"+id+"/cmdline"); // this is my own process, so I always have the right permissions
			//			p.waitFor();
			//
			//			BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
			//
			//			while ((line = reader.readLine())!= null) {
			//				sb.append(line + "\n");
			//			}

			BufferedReader br = new BufferedReader(new FileReader("/proc/"+id+"/cmdline"));
			try {
				line = br.readLine();
			} finally {
				br.close();
			}
			appName = line.split("\0")[0];
		} catch (IOException e) {
			e.printStackTrace();
		}
		return appName;
	}

	/**
	 * get the Source dir of the given package
	 * @param packageName 
	 * @param c the current context
	 * @return the source dir of packageName
	 */
	private static String getSourceDir(String packageName, Context c) {
		String sourceDir = null;
		try {
			sourceDir = c.getApplicationContext().getPackageManager().getApplicationInfo(packageName,0).sourceDir;
		} catch (NameNotFoundException e1) {
			e1.printStackTrace();
		}
		return sourceDir;
	}

	/**
	 * get the Source dir of the given package without a context (slow variant)
	 * @param packageName 
	 * @return the source dir of packageName
	 */
	private static String getSourceDirSlow(String packageName) {
		String sourceDir = null;
		try {
			// this only works if bash and egrep are available on the device!
			ProcessBuilder pb = new ProcessBuilder("bash", "-c", "pm list packages -f | egrep ="+packageName+"$");
			Process p = pb.start();
			p.waitFor();

			BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));

			// we are only interested in the first line
			String line = reader.readLine();
			if (line == null) {
				Log.e(TAG, "Package not found!");
			} else {
				sourceDir = line.substring(8, line.lastIndexOf('='));
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		return sourceDir;
	}
	
	/**
	 * get the Source dir of the given package without a context (faster variant)
	 * @param packageName 
	 * @return the source dir of packageName
	 */
	private static String getSourceDirFast(String packageName) {
		PathClassLoader pathClassLoader = new dalvik.system.PathClassLoader(
				"/system/framework/framework.jar",
				ClassLoader.getSystemClassLoader());

		String sourceDir = null;
		try {
			// hidden API magic ahead:
			
			Class<?> class_ServiceManager = Class.forName("android.os.ServiceManager", true, pathClassLoader);
			Method method_getService = class_ServiceManager.getMethod("getService", String.class);
			Object object_IBinder = method_getService.invoke(null, new String("package"));

			Class<?> class_IPackageManagerStub = Class.forName("android.content.pm.IPackageManager$Stub", true, pathClassLoader);
			Class<?> class_IBinder = Class.forName("android.os.IBinder", true, pathClassLoader);
			Method method_asInterface = class_IPackageManagerStub.getMethod("asInterface", class_IBinder);
			Object object_ServiceManager = method_asInterface.invoke(null, object_IBinder);

			Method method_getInstalledPackages = object_ServiceManager.getClass().getMethod("getInstalledPackages", int.class, int.class);

			Class<?> class_ParceledListSlice = Class.forName("android.content.pm.ParceledListSlice", true, pathClassLoader);
			Method method_getList = class_ParceledListSlice.getMethod("getList");

			int flags = 0;
			Object object_ParceledListSlice = method_getInstalledPackages.invoke(object_ServiceManager, flags, 0);
			ArrayList<PackageInfo> packageInfos = (ArrayList<PackageInfo>) method_getList.invoke(object_ParceledListSlice);

			// we now have all installed packages and can iteratively search for the needed one
			for (PackageInfo pi : packageInfos) {
				if (pi.packageName.equals(packageName)) {
					sourceDir = pi.applicationInfo.publicSourceDir;
					break;
				}
			}

		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchMethodException e) {
			e.printStackTrace();
		} catch (IllegalAccessException e) {
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
		} catch (InvocationTargetException e) {
			e.printStackTrace();
		}
		return sourceDir;
	}

	/**
	 * @param packageName
	 * @return the calling class and function
	 */
	private static String getCaller(String packageName) {
		StackTraceElement[] cause = Thread.currentThread().getStackTrace();
		for (StackTraceElement stackTraceElement : cause) {
			Log.e(TAG + " Caller Stacktrace", stackTraceElement.toString());
		}
		String caller = null;
		try {
			for(int i = 0; i < cause.length; i++) {
				if (cause[i].toString().startsWith("com.example.library.Library.test")) { // this is the called function
					// check if the function is called by reflection
					if (cause[i+1].toString().startsWith("java.lang.reflect.Method.")) {
						int j = i+1;
						for(; j < cause.length-1; j++) {
							if (!cause[j].toString().startsWith("java.lang.reflect.Method.")) {
								break;
							}
						}
						caller = cause[j].toString();
					} else {
						caller = cause[i+1].toString();
					}
					caller = caller.substring(0, caller.indexOf('('));
					return caller;
				}
			}
		} catch (IndexOutOfBoundsException e) {
			// lazy checking...
			Log.e(TAG, "Stack trace format not recognized.");
		}
		return null;
	}
	
	/**
	 * Convert a byte array to a nice String
	 * @param in the byte array
	 * @return a String representing the byte array
	 */
	@SuppressLint("DefaultLocale")
	private static String bytesToHex(byte[] in) {
		final StringBuilder builder = new StringBuilder();
		for(byte b : in) {
			builder.append(String.format("%02x", b).toUpperCase());
			builder.append(":");
		}
		return builder.substring(0, builder.length()-1);
	}

	/**
	 * the actual verification of the caller.
	 * This function basically checks if the caller performed a signature check of the library right before loading the package into a classloader
	 * @return
	 */
	private static boolean perform_caller_verification() {
		String packageNameCaller = getCallingAppName();
		
//		long time_in_smali = 0, bef, after;

		String callerClassAndMethod = getCaller(packageNameCaller);
		String fullclass = callerClassAndMethod.substring(0, callerClassAndMethod.lastIndexOf(".")).replace('.', '/');
		String method    = callerClassAndMethod.substring(callerClassAndMethod.lastIndexOf(".")+1);

		String sourceDirCaller = getSourceDirFast(packageNameCaller);

		// For this demonstrator, the calling class will be baksmalied into a temporary folder
		// !!ATTENTION: this is not save and has to be changed in production. 
		// To solve this, baksmali can be modified to directly print the code for a specific class without the need for a file
		File outputDir = getContext().getCacheDir(); // context being the Activity pointer
		String temp = outputDir + File.separator + "source";
		try {
			File outputFile = new File(temp);
			outputFile.mkdir();
		} catch (Exception e1) {}

		// disassemble only the calling class
		try {
			Log.d(TAG, "Calling " + sourceDirCaller + " -C " + "L"+fullclass  + " -o " + temp);
//			bef = System.currentTimeMillis();
			org.jf.baksmali.main.main(new String[]{sourceDirCaller, "-C", "L"+fullclass ,"-o", temp});
//			after = System.currentTimeMillis();
//			time_in_smali += (after-bef);
		} catch (Exception e) {
			e.printStackTrace();
		}

		// parse the disassembly of the calling function (not the whole class!)
		File sourceFile = new File(temp + File.separator + fullclass + ".smali");
		ArrayList<String> code = new ArrayList<String>();
		BufferedReader bufferedReader = null;
		try {
			FileInputStream fis = new FileInputStream(sourceFile);
			InputStreamReader isr = new InputStreamReader(fis);
			bufferedReader = new BufferedReader(isr);
			String line;
			boolean inside_correct_function = false;
			while ((line = bufferedReader.readLine()) != null) {
				if (line.startsWith(".method") && line.contains(" " + method + "(")) {
					inside_correct_function = true;
				}  
				if (inside_correct_function) {
					if (!line.trim().startsWith(".") && line.trim().length() > 0) { // hide comments and empty lines
						code.add(line.trim());
					}
				}
				if (line.startsWith(".end method")) {
					inside_correct_function = false;
				}
			}
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {bufferedReader.close();}catch(Exception e) {}
		}
		
		if (code.size() == 0) {
			Log.e(TAG, "method not found");
			return false;
		}

		// now we have the code and can check if it verifies the library before loading it.
		ArrayList<String> verifiers = new ArrayList<String>();
		if (!verify_method_smali_magic(code, verifiers) ) {
			return false;
		}
		
		// verifiers now contains at least one verifier. we check all of them if they are the provided ones.
		for (String verifier : verifiers) {
			String classname = verifier.substring(0, verifier.indexOf(";")).replace('.', '/');
			
			// disassemble only the verifier
			try {
				Log.d(TAG, "Calling " + sourceDirCaller + " -C " + "L"+classname  + " -o " + temp);
//				bef = System.currentTimeMillis();
				org.jf.baksmali.main.main(new String[]{sourceDirCaller, "-C", "L"+classname ,"-o", temp});
//				after = System.currentTimeMillis();
//				time_in_smali += (after-bef);
			} catch (Exception e) {
				e.printStackTrace();
			}
			
			// parse the disassembly (almost whole class, ommiting comments and package, super and class name)
			sourceFile = new File(temp + File.separator + classname + ".smali");
			code.clear();
			try {
				FileInputStream fis = new FileInputStream(sourceFile);
				InputStreamReader isr = new InputStreamReader(fis);
				bufferedReader = new BufferedReader(isr);
				String line;
				StringBuffer sb = new StringBuffer();
				boolean inside_functions = false;
				while ((line = bufferedReader.readLine()) != null) {
					line = line.trim();
					if(line.startsWith(".")) {
						continue;
					}
					if (inside_functions) {
						sb.append(line);	
					}
					if(line.startsWith("# direct methods")) { // we ommit all above the methods, (=package, super and class name)
						inside_functions = true;
					}
				}
				// calculate the SHA256 of the code
				MessageDigest md = MessageDigest.getInstance("SHA256");
				md.update(sb.toString().getBytes());
				String key = bytesToHex(md.digest());
				// only if the code has this signature is it the correct file. 
				// Typically a library fendor would provide the library user with the verification class, 
				// so a app developer would only have to include the class and not change anything 
				// -> the signature stays intact
				if (!key.equals("C5:F5:41:2A:4B:E0:03:D4:FE:BC:B4:C4:C3:9E:CD:03:50:A2:34:02:09:62:D1:7F:9F:02:29:13:6A:7B:24:6B")) {
					Log.e(TAG, "verifier signature is wrong: " + key);
					return false;
				} else {
					Log.i(TAG, "verifier "+verifier+" ok");
				}

			} catch (FileNotFoundException e1) {
				e1.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} finally {
				try {bufferedReader.close();}catch(Exception e) {}
			}
		}
		//Log.i(TAG + " timing", "time spent in baksmali: " + time_in_smali + "ms.");
		return true;
	}

	/**
	 * analyzes the given code and returns the verifiers which are called right before the library loading (if any)
	 * @param code the code to be checked
	 * @param verifiers[out] data structure to return the verifiers
	 * @return returns true if a verifier is found, or false if none is found, or the structure of the code is not correct
	 */
	private static boolean verify_method_smali_magic(final ArrayList<String> code, final ArrayList<String> verifiers) {
		// each package loading is searched in the smali
		try {
			// the package name of this library. This is used to only check for verifications of this library
			final String library_packageName = "com.example.library";
			ArrayList<Integer> foundLocations = new ArrayList<Integer>();
			for(int i = 0; i < code.size(); i++) {
				String string = code.get(i);
				// get all locations that are loading the library (e.g. for further use in a classloader)
				// at least one of this locations exist, since this library has been called
				if (string.startsWith("invoke-virtual") && string.contains("Landroid/content/pm/PackageManager;->getApplicationInfo(")) {
					foundLocations.add(i);
				}
			}
			/* code analysis of the calling function. A correct implementation would look like this in Java:
			   if (Verifier.verify(c, "com.example.library")) {
					String apkName = c.getPackageManager().getApplicationInfo("com.example.library",0).sourceDir;
					...
				}
				Where c is the current context.
				In Smali this will translate to:
				
				const-string v8, "com.example.library"
				invoke-static {v1, v8}, Lcom/example/library_caller/Verifier;->verify(Landroid/content/Context;Ljava/lang/String;)Z
				move-result v8
				if-eqz v8, :cond_5d
				invoke-virtual {v1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;
				move-result-object v8
				const-string v9, "com.example.library"
				const/4 v10, 0x0
				invoke-virtual {v8, v9, v10}, Landroid/content/pm/PackageManager;->getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;
			 * 
			 *   This is checked in the following lines, and all calls to Verifiers will be returned (in this example Lcom/example/library_caller/Verifier;->verify)
			 */
			Pattern pattern = Pattern.compile("invoke-virtual \\{v[0-9]+, (v[0-9]+), v[0-9]+\\}");
			int verified_loadings = 0;
			for (Integer i: foundLocations) {
				Matcher matcher = pattern.matcher(code.get(i));
				if (matcher.find()) {
					String param = matcher.group(1);
					if(		!code.get(i-1).startsWith("const/4") ||
							!code.get(i-2).equals("const-string "+param+", \""+library_packageName+"\"") ||
							!code.get(i-3).startsWith("move-result-object") ||
							!code.get(i-4).startsWith("invoke-virtual") ||
							!code.get(i-5).startsWith("if-eqz") ||
							!code.get(i-6).startsWith("move-result") ||
							!code.get(i-7).startsWith("invoke-static") ||
							!code.get(i-8).startsWith("const-string")) {
						Log.e(TAG, "failed 1");
						break;
					}
					Matcher if_matcher = Pattern.compile("if-eqz (v[0-9]+), ").matcher(code.get(i-5));
					Matcher move_result_matcher = Pattern.compile("move-result (v[0-9]+)").matcher(code.get(i-6));
					Matcher invoke_matcher = Pattern.compile("invoke-static \\{v[0-9]+, (v[0-9]+)\\}, L(.*)\\(Landroid/content/Context;Ljava/lang/String;\\)").matcher(code.get(i-7));
					Matcher const_string_matcher = Pattern.compile("const-string (v[0-9]+), \""+library_packageName+"\"").matcher(code.get(i-8));

					if (	!if_matcher.find() ||
							!move_result_matcher.find() ||
							!invoke_matcher.find() ||
							!const_string_matcher.find()) {
						Log.e(TAG, "failed 2");
						break;
					}
					if (	!if_matcher.group(1).equals(move_result_matcher.group(1)) ||
							!invoke_matcher.group(1).equals(const_string_matcher.group(1))) {
						Log.e(TAG, "failed 3");
						break;
					}
					verifiers.add(invoke_matcher.group(2));
					Log.i(TAG, "ok. Verifier is "+invoke_matcher.group(2));
					verified_loadings++;
				}
			}
			if (verified_loadings != foundLocations.size()) {
				Log.e(TAG, "Error: not all library calls are verified ("+verified_loadings+"!="+foundLocations.size()+")!");
				return false;
			} else {
				return true;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	/**
	 * this is the actual public library function which can be called by other apps.
	 * But it will only perform its real task, if the caller correctly verifies this library. 
	 */
	public static void test() {
		Application c = getContext();
		
		long before = System.currentTimeMillis();
		boolean verified = perform_caller_verification(); // the actual verification
		long after = System.currentTimeMillis();
		Log.i(TAG + " timing", "successful verification took " + (after-before) + "ms.");
		/*Benchmarks, all times in ms
		 * Galaxy Nexus (GT-I9250), Android 4.4.4:
		 *   successful verification
		 *     544, 547, 536, 468, 569, 486, 609, 448, 461, 483
		 *     568, 539, 487, 515, 511, 484, 513, 535, 504, 543
		 *     540, 475, 453, 517, 458, 460, 499, 569, 517, 485
		 *   failed verification
		 *     465, 356, 414, 399, 356, 352, 461, 346, 418, 443
		 *     486, 400, 369, 359, 344, 420, 381, 394, 359, 422
		 *     502, 516, 462, 424, 395, 422, 411, 429, 472, 387
		 * 
		 * Galaxy Nexus S (GT-I9023), Android 4.4.4:
		 *   successful verification
		 *     947, 775, 720, 691, 744, 724, 755, 736, 752, 725
		 *     940, 772, 800, 719, 762, 735, 758, 728, 827, 743
		 *     794, 791, 773, 805, 820, 830, 761, 770, 797, 790
		 *   failed verification
		 *     690, 513, 577, 501, 491, 508, 587, 470, 488, 527
		 *     524, 604, 516, 644, 497, 509, 533, 529, 661, 560
		 *     541, 511, 536, 594, 573, 562, 560, 665, 511, 518
		 *     
		 * Motorola Nexus 6, Android 5.0:
		 *   successful verification
		 *     267, 214, 242, 226, 201, 188, 231, 225, 223, 213
		 *     219, 194, 237, 248, 210, 210, 223, 244, 252, 225
		 *     232, 266, 236, 239, 253, 238, 245, 225, 234, 234
		 *   failed verification
		 *     189, 203, 202, 195, 199, 255, 183, 190, 203, 226
		 *     214, 196, 195, 224, 203, 221, 213, 199, 195, 206
		 *     205, 205, 236, 249, 203, 206, 190, 218, 211, 253
		 *   with baksmali timing; time in brackets is the time spent baksmaling, time in front of the bracket is the corresponding total time
		 *     247 (203), 234 (184), 237 (196), 272 (218), 236 (191), 236 (190), 222 (179), 238 (199), 247 (206), 232 (188)
		 *     235 (192), 232 (189), 241 (186), 227 (185), 202 (156), 259 (212), 216 (173), 219 (178), 247 (206), 263 (202)
		 *     251 (197), 235 (188), 230 (189), 230 (185), 290 (231), 241 (199), 235 (193), 240 (194), 248 (200), 250 (202)
		 *     Average time spent in baksmali: 80.8%
		 */
		if (verified) {
			Log.d(TAG, "this would be the normal to-be-executed code");
			if (c != null) {
				Toast t = Toast.makeText(c, "Library executed", Toast.LENGTH_LONG);
				t.show();
			}
			// do_something.
		} else {
			Log.e(TAG, "caller could not be verified. Aborting.");
			if (c != null) {
				Toast t = Toast.makeText(c, "Library refused to load. Verification failure.", Toast.LENGTH_LONG);
				t.show();
			}
		}
	}

}
