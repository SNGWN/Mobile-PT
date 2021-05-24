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
