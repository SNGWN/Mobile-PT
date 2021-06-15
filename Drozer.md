# Installation
  --> wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
  --> sudo python2.7 get-pip.py
  --> pip2.7 install drozer

# Setup Drozer
  --> Forward Port for Connection b/w Android Server and Machine
      **--> adb forward tcp:31415 tcp:31415**
  --> Connect with Server
      **--> drozer console connect**

# Package List
  --> run app.package.list -f <search string>

# Identify Attack Surface
  --> run app.package.attacksurface <package name>

# List Out all Activities for that package
  --> run app.activity.info -a <package Name>

# Run a specific Activity from Application
  --> run app.activity.start --component <package Name> <Activity Name>

# View Content Provide permission
  --> run app.provider.info <package name>

# Content Provide Scanning for Information Leakage and Injection
  --> run scanner.provider.injection -a <package name>                              **Injection**
  --> run scanner.provider.finduris -a <package name>                               **Find URI's**
  --> run scanner.provider.sqltables -a <package name>                              **Enumerate Table Name**
  --> run scanner.provider.traversal -a <package name>                              **Table Traversal**
