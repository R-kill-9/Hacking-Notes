**Tapjacking** (Android equivalent of clickjacking) is an interface-level attack where a malicious app tricks a user into tapping UI controls belonging to a different app by overlaying or otherwise obscuring the real UI. The user thinks they tapped a harmless control but actually triggered a sensitive action in the background app. This can lead to unintended permission grants, purchases, or destructive operations.

## Dynamic Analysis[¶](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0035/#dynamic-analysis "Permanent link")

Abusing this kind of vulnerability on a dynamic manner can be pretty challenging and very specialized as it closely depends on the target Android version. For instance, for versions up to Android 7.0 (API level 24) you can use the following APKs as a proof of concept to identify the existence of the vulnerabilities.

#### Tapjacker
[TapJacker](https://github.com/dzmitry-savitski/tapjacker) is a lightweight, ready-to-run proof-of-concept tool that demonstrates Android tapjacking attacks. Inspired by the QARK project, it was built to provide a simple, no-build way to reproduce overlay-based UI deception for defensive research and testing.

To use it, simply download the APK from the project repository, install it on the device that has the target app, select the package you want to target, and then launch the APK.

![](Tapjacker.png)

## Static Analysis[¶](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0035/#static-analysis "Permanent link")

To start your static analysis you can check the app for the following methods and attributes (non-exhaustive list):

- Override [`onFilterTouchEventForSecurity` ↗](https://developer.android.com/reference/android/view/View#onFilterTouchEventForSecurity%28android.view.MotionEvent%29 "onFilterTouchEventForSecurity") for more fine-grained control and to implement a custom security policy for views.
- Set the layout attribute [`android:filterTouchesWhenObscured` ↗](https://developer.android.com/reference/android/view/View#attr_android:filterTouchesWhenObscured "android:filterTouchesWhenObscured") to true or call [`setFilterTouchesWhenObscured` ↗](https://developer.android.com/reference/android/view/View.html#setFilterTouchesWhenObscured%28boolean%29 "setFilterTouchesWhenObscured").
- Check [FLAG_WINDOW_IS_OBSCURED ↗](https://developer.android.com/reference/android/view/MotionEvent.html#FLAG_WINDOW_IS_OBSCURED "FLAG_WINDOW_IS_OBSCURED") (since API level 9) or [FLAG_WINDOW_IS_PARTIALLY_OBSCURED ↗](https://developer.android.com/reference/android/view/MotionEvent.html#FLAG_WINDOW_IS_PARTIALLY_OBSCURED "FLAG_WINDOW_IS_PARTIALLY_OBSCURED") (starting on API level 29).

Some attributes might affect the app as a whole, while others can be applied to specific components. The latter would be the case when, for example, there is a business need to specifically allow overlays while wanting to protect sensitive input UI elements. The developers might also take additional precautions to confirm the user's actual intent which might be legitimate and tell it apart from a potential attack.

As a final note, always remember to properly check the API level that app is targeting and the implications that this has. For instance, [Android 8.0 (API level 26) introduced changes ↗](https://developer.android.com/about/versions/oreo/android-8.0-changes#all-aw "Alert windows") to apps requiring `SYSTEM_ALERT_WINDOW` ("draw on top"). From this API level on, apps using `TYPE_APPLICATION_OVERLAY` will be always [shown above other windows ↗](https://developer.android.com/about/versions/oreo/android-8.0-changes#all-aw "Alert Windows") having other types such as `TYPE_SYSTEM_OVERLAY` or `TYPE_SYSTEM_ALERT`. You can use this information to ensure that no overlay attacks may occur at least for this app in this concrete Android version.