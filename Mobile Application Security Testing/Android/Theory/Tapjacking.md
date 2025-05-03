**Tapjacking** is a type of **UI redressing attack** in Android where a malicious app overlays transparent or partially transparent elements over legitimate app interfaces to trick users into tapping buttons or granting permissions without realizing it.

### How It Works

- An attacker creates a malicious app that shows a **transparent layer** (such as a fake button or image) over another app or system dialog.
    
- The victim thinks they are interacting with a harmless interface, but they are actually tapping on a **hidden target** underneath, such as:
    
    - Installing an app
        
    - Granting permissions
        
    - Changing security settings
        

### Technical Details

- Implemented using Android features like `Toast`, `AlertDialog`, or specially configured `View` overlays with `TYPE_APPLICATION_OVERLAY` or deprecated `TYPE_SYSTEM_ALERT`.
    
- The attacker uses the `FLAG_NOT_FOCUSABLE` and `FLAG_NOT_TOUCH_MODAL` window flags to let touch events pass through to the app below.
    

### Common Exploitation Scenarios

- Triggering installation of malicious apps
    
- Granting device admin access
    
- Clicking on in-app purchase confirmations
    
- Changing app settings without consent
    

### Mitigations

- Android 4.0.3+ introduced `filterTouchesWhenObscured="true"` in layout XML or `View.setFilterTouchesWhenObscured(true)` in code, which can block taps when the view is obscured.
    
- Apps should perform additional checks in `onFilterTouchEventForSecurity()` to detect and prevent such conditions.
    
- Google Play may reject apps using SYSTEM_ALERT_WINDOW without clear justification.
    

### Example XML Defense