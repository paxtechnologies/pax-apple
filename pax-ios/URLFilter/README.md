# URL filter (phase 2, iOS 26+, not built yet)

A system-wide URL filter that works on unmanaged iPhones (Network Extension URL filter,
`NEURLFilterManager` + an `NEURLFilterControlProvider` app extension). It needs:

- a PIR server next to api.paxpeace.com (Apple's open-source `pir-service-example`),
- a Bloom filter built from the Pax lists, served to the extension,
- Apple onboarding (`apple-url-filter=org.paxpeace.pax` DNS TXT record; PIR service URLs
  declared in Info.plist from iOS 27.3),
- an Xcode 26 "URL Filter" extension target (bundle ID `org.paxpeace.pax.url-filter`).

`URLFilterControlProvider.swift.txt` is a starting point, kept out of the build until the
target is added. 
