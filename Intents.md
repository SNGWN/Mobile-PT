# Intents :-:
    An intent is an abstract description of an operation to be performed. It can be used with *startActivity* to launch an Activity, *broadcastIntent* to send it to any interested BroadcastReceiver components, and *Context.startService(Intent)* or *Context.bindService(Intent, ServiceConnection, int)* to communicate with a background Service.
  **Fundamental Use Cases of Intents**
    - Start and Activity
    - Starting a Service
    - Delivering a Broadcast

  **Intent Types**
    - *Explicit Intents* :-: Intent that specify which application will satisfy the intent, by supplying either the target app's package name or a fully-qualified component class name.
    - *Implicit Intents* :-: In Implicit Intents we do not name a specific component, but instead declare a general action to perform, which allows a component from another app to handle it. For example, if you want to show the user a location on a map, you can use an implicit intent to request that another capable app show a specified location on a map.

# Elements of an Intent :-:
  An Intent object carries information that the Android system uses to determine which component to start (such as the exact component name or component category that should receive the intent), plus information that the recipient component uses in order to properly perform the action (such as the action to take and the data to a ct upon).
    - **Action** :-: The general action to be performed, such as *ACTION_VIEW*, *ACTION_EDIT*, *ACTION_MAIN*, etc.

    - **Data** :-: The data to operate on, such as a person record in the contacts database, expressed as a Uri.

    - **Category** :-: Gives additional information about the action to execute. For example, *CATEGORY_LAUNCHER* means it should appear in the Launcher as a top-level application, while *CATEGORY_ALTERNATIVE* means it should be included in a list of alternative actions the user can perform on a piece of data.

    - **Type** :-: Specifies an explicit type *(a MIME type)* of the intent data. Normally the type is inferred from the data itself. By setting this attribute, you disable that evaluation and force an *explicit* type.

    - **Component Name** :-: The name of the component to start, meaning that the intent should be delivered only to the app component defined by the component name.

    - **Extras** :-: This is a Bundle of any additional information. This can be used to provide extended information to the component. For example, if we have a action to send an e-mail message, we could also include extra pieces of data here to supply a subject, body, etc.
