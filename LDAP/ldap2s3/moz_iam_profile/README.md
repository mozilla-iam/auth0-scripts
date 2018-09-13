# moz_iam_profile

This library is a dynamic class-constructor for the Mozilla IAM profiles (v2).
It takes the Mozilla IAM default profile and schema, and creates a Python class from it dynamically.

This means that the default profile (JSON file: user_profile_core_plus_extended.json) and schema can be changed without
affecting the class code. It allows for directly loading it from https://github.com/mozilla-iam/cis.

## Example usage

```
from moz_iam_profile import User
skel_user = User(user_id="bobsmith")
skel_user.user_id.value = "notbobsmith"
if skel_user.validate():
  profile = skel_user.as_json()
```
