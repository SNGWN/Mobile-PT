# Installation
  curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py; python2 get-pip.py; pip2.7 install protobuf; pip2.7 install pyOpenSSL; git clone https://github.com/hamcrest/PyHamcrest.git; cd PyHamcrest;sudo python3 setup.py install;cd; sudo pip2.7 install Twisted;

  # To install Drozer, execute 1 of below command
      1). wget https://github.com/mwrlabs/drozer/releases/download/2.4.4/drozer-2.4.4-py2-none-any.whl; sudo pip2.7 install drozer-2.4.4-py2-none-any.whl
      2). pip install drozer
      
# Setup Drozer
  --> Forward Port for Connection b/w Android Server and Machine
      **--> adb forward tcp:31415 tcp:31415**
  --> Connect with Server
      **--> drozer console connect**

# Package List
  --> run app.package.list -f <search string>

# List Applications that offer Debugging functionality to User, with their Permissions and UID.
  --> run app.package.debuggable

# List Applications that have Backup functionality. This will also list out UID and API Key if they are Synchronize data with cloud.  
  --> run app.package.backup

# Figure out main Activity Call Intent (Ex. Package :-: jakhar.aseem.diva)
  --> run app.package.launchintent jakhar.aseem.diva

# Print Andoridmanifest.xml File (Ex. Package :-: jakhar.aseem.diva)
  --> run app.package.manifest jakhar.aseem.diva

# List out Native Libraries (Ex. Package :-: jakhar.aseem.diva)
  --> run app.package.native jakhar.aseem.diva

# List out Package and its Permissions with UID (Ex. UID = 10010)
  --> run app.package.shareduid -u 10010

# Identify Attack Surface
  --> run app.package.attacksurface <package name>

# List Out Activities of that package with intent filters and intent Permissions (-i for Intents) and (-v for verbosity)
  --> run app.activity.info -a <package Name> -i -v

# Run a specific Activity from Application
  --> run app.activity.start --component <package Name> <Activity Name>

# View Content Provide permission
  --> run app.provider.info <package name>

# View Content Provider Content
  --> run app.provider.query <content provider URI>

# Content Provide Scanning for Information Leakage and Injection
  --> run scanner.provider.finduris -a <package name>                               **Find URI's**
  --> run scanner.provider.injection -a <package name>                              **Injection**
  --> run scanner.provider.sqltables -a <package name>                              **Enumerate Table Name**
  --> run scanner.provider.traversal -a <package name>                              **Table Traversal**

# List Broadcasts from Application Package (Ex. Application :-: com.android.dialer)
  --> run app.broadcast.info -a com.android.dialer

# Sniff Broadcasts Receiver (Ex. Action :-: AIRPLANE_MODE_CHANGE)
  --> run app.broadcast.sniff --action AIRPLANE_MODE_CHANGE

# Get Service List
  --> run app.service.info -a <package> -iuv
