# AlwaysEncryptedIdentity
An extension of ASP .NET Identity system to work with Always Encrypted feature

Disclaimer

This project was created to interconnect Always Enctypted feature with Identity membership system.
There is still work to be done and if someone wants to contribute, he/she is free to email me.

The features that work with Always Encrypted using this nuget are:

* Register
* Sign in
* Log off
* Email Confirmation
* Change password
* Recover password

If you would like to customize AspNetUsers table by adding more columns, then you must write extra code to fill these columns when registering a user.

It is necessary to create a model including the tables AspNetRoles, AspNetUserRoles and AspNetUsers, using dbo Schema.

The nuget could further extend to make the Role Manager work with Always Encrypted, but since the above tables are included in the model, one can manage user roles by using that model.
