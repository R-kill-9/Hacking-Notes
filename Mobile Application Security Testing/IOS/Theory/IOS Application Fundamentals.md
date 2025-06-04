An iOS application consists of a main executable bundled with resources and configuration files. It follows a component-based architecture where key modules are managed by the system runtime and the developer provides custom behavior by subclassing and overriding specific methods.

The entry point is the `main()` function, which typically delegates to `UIApplicationMain`, launching the app and setting up the main event loop.

## Info.plist (iOS equivalent of AndroidManifest.xml)
Every iOS app includes an `Info.plist` file (Information Property List) that contains essential configuration data used by the system at runtime. It defines:

- The app’s bundle identifier
- Supported interface orientations
- Permissions the app requires (e.g., location, camera)
- Entry points such as main storyboard or main class
- Capabilities such as background modes, push notifications
- Custom URL schemes for deep linking

```xml
<key>CFBundleIdentifier</key>
<string>com.example.myapp</string>

<key>NSCameraUsageDescription</key>
<string>This app needs camera access to take photos</string>

<key>UIApplicationSceneManifest</key>
<dict>
    <!-- Scene configuration -->
</dict>
```

Unlike Android, where permissions are declared via `<uses-permission>`, in iOS they are declared using human-readable keys such as `NSLocationWhenInUseUsageDescription` or `NSPhotoLibraryUsageDescription`. These are required for runtime authorization prompts to be shown to the user.

This file plays a central role in app security, permissions, integration, and lifecycle behavior.


---


## Core Components
iOS applications are built using the following core components:

- **UIApplication**
- **UIApplicationDelegate**
- **UIWindow**
- **UIViewController**
- **UIView**

These components cooperate to manage the lifecycle, user interface, and interaction with the system.


#### UIApplication  
`UIApplication` is a singleton that represents the running app and acts as the central control point. It handles:

- App-level events (e.g., backgrounding, memory warnings)
- Touch event distribution
- Status bar and app-wide UI state

You do not subclass `UIApplication` in most apps. Instead, you interact with it via the `UIApplication.shared` instance and through the app delegate.


#### UIApplicationDelegate  
This protocol defines methods that respond to important runtime events. A custom class (typically named `AppDelegate`) conforms to this protocol and is set in `@UIApplicationMain`.

Main responsibilities include:

- Configuring app state at launch (`didFinishLaunchingWithOptions`)
- Responding to state transitions (background/foreground)
- Handling push notification registration
- Managing background tasks

```swift
func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
    // App initialization logic
    return true
}
```

#### UIWindow  
`UIWindow` is a container for views and view controllers. An app typically has one key window, and this window displays the content of the currently active view controller.

The window is created and assigned in the app delegate:
```swift
window = UIWindow(frame: UIScreen.main.bounds)
window?.rootViewController = MyViewController()
window?.makeKeyAndVisible()
```

#### UIViewController  
A `UIViewController` is a controller object that manages a single screen's worth of content. It acts as the intermediary between the app's logic and its UI (the view hierarchy).

View controllers are fundamental to navigation, screen transitions, and encapsulation of behavior.

Lifecycle methods include:

- `viewDidLoad()`: Called after the view is loaded into memory.
- `viewWillAppear()`: Called before the view appears.
- `viewDidAppear()`: Called after the view appears.
- `viewWillDisappear()`: Called before the view disappears.
- `viewDidDisappear()`: Called after the view disappears.


#### UIView  
`UIView` is the base class for all visual elements on the screen. Every UI element inherits from `UIView`, including labels, buttons, text fields, and custom components.

Views are organized in a hierarchy and are responsible for:

- Rendering content
- Handling touch events
- Animations and layout    

You can subclass `UIView` to implement custom drawing or interaction behavior.


---


## Component Communication  
iOS follows an event-driven model. Components communicate using:

- **Delegation**: One object acts on behalf of another (e.g., `UITableViewDelegate`).
- **Target-Action**: UI elements send messages to specified methods.
- **Notifications**: Broadcast-style messaging via `NotificationCenter`.
- **Closures**: Inline callbacks used extensively in modern Swift.    

---

## Navigation  
View controllers can be composed and navigated in several ways:

- **UINavigationController**: Stack-based navigation
- **UITabBarController**: Tab-based switching
- **Modal Presentation**: Temporary screen overlay via `present(_:animated:)`
- **Storyboard Segues**: Visual and logical transitions between screens    

---

## Data Flow and Model Layer  
iOS apps typically follow MVC (Model-View-Controller), though MVVM and other patterns are also used. The model layer represents the app's data and business logic, separate from UI logic.

Persistence is often handled using:

- **UserDefaults**: For small key-value storage
- **FileManager**: For files
- **Core Data**: For object-graph and persistence
- **Keychain**: For secure data

---

## Lifecycle Overview  
iOS applications follow a well-defined lifecycle:

1. **Not Running**: App is not launched or was terminated.
2. **Inactive**: App is running but not receiving events.
3. **Active**: App is in the foreground and receiving input.
4. **Background**: App is running code in the background.
5. **Suspended**: App is in memory but not executing code.

Transitions between these states are triggered by system events and are handled via delegate methods.

---

## Multitasking and Background Execution  
iOS restricts background activity to preserve battery. Apps may register for background execution for specific tasks:

- Location update    
- Audio playback
- VoIP
- Background fetch
- Silent push notifications

Use of `BGAppRefreshTask` and `BGProcessingTask` (iOS 13+) allows scheduled work in the background.

---

## Security Model  
Each app runs in its own sandbox, limiting access to:

- File system (only app-specific directories)
- Hardware (must request explicit permission)
- Inter-app communication (restricted and audited)

Permissions are requested at runtime and must be justified in `Info.plist`.