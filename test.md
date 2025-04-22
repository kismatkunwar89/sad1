```json
{
  "@context": {
    "kb": "http://example.org/kb/",
    "uco-core": "https://ontology.unifiedcyberontology.org/uco/core/",
    "uco-identity": "https://ontology.unifiedcyberontology.org/uco/identity/",
    "uco-observable": "https://ontology.unifiedcyberontology.org/uco/observable/",
    "uco-types": "https://ontology.unifiedcyberontology.org/uco/types/",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "acme": "http://example.org/acme#"
  },
  "@graph": [
    {
      "@id": "kb:file-3c4b02b1-58a1-4e0f-a37b-0f6c1b7be048",
      "@type": "uco-observable:File",
      "uco-core:hasFacet": [
        {
          "@id": "kb:filefacet-4268dc38-6f23-4c20-a9bb-9e79b0377b33",
          "@type": "uco-observable:FileFacet",
          "uco-observable:fileName": "CCleaner.lnk",
          "uco-observable:filePath": "C:\\Users\\Public\\Desktop\\CCleaner.lnk",
          "uco-observable:extension": "lnk",
          "uco-observable:observableCreatedTime": {
            "@type": "xsd:dateTime",
            "@value": "2019-07-02T20:41:22.095Z"
          },
          "uco-observable:modifiedTime": {
            "@type": "xsd:dateTime",
            "@value": "2019-07-02T20:41:22.110Z"
          },
          "uco-observable:accessedTime": {
            "@type": "xsd:dateTime",
            "@value": "2019-07-02T20:41:22.110Z"
          }
        },
        {
          "@id": "kb:lnkfacet-2b705d9f-5745-4d51-8b9e-b26aaccb0ff0",
          "@type": [
            "acme:LnkFacet",
            "uco-core:Facet"
          ],
          "acme:targetPath": "C:\\Program Files\\CCleaner\\CCleaner64.exe",
          "acme:targetCreatedTime": {
            "@type": "xsd:dateTime",
            "@value": "2019-06-18T13:53:06.000Z"
          },
          "acme:targetModifiedTime": {
            "@type": "xsd:dateTime",
            "@value": "2019-06-18T13:53:06.000Z"
          },
          "acme:targetAccessedTime": {
            "@type": "xsd:dateTime",
            "@value": "2019-07-02T20:41:21.000Z"
          },
          "acme:targetSizeInBytes": {
            "@type": "xsd:nonNegativeInteger",
            "@value": 22695280
          },
          "acme:targetAttributes": "FILE_ATTRIBUTE_ARCHIVE",
          "uco-observable:driveType": "DRIVE_FIXED",
          "uco-observable:volumeID": "8ABED97A"
        }
      ]
    }
  ]
}

