# IdentityServer4 certificate creator

Based on https://damienbod.com/2020/02/10/create-certificates-for-identityserver4-signing-using-net-core/

Easily create different kind of certificate for **IdentityServer**

To build as a single file application, please run the following command:

```bash
 dotnet publish -r win-x64 -p:PublishSingleFile=true -c Release
```

```bash
 dotnet publish -r linux-x64 -p:PublishSingleFile=true -c Release
```

How to run:
```bash
IdentityServer4.Certificate.Creator.exe -d my-dns.com -p MySecurePassword -c Ecdsa -v 20
```
