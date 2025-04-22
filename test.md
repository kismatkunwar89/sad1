```json
{
  "@context": {
    "kb": "http://example.org/kb/",
    "uco-core": "https://ontology.unifiedcyberontology.org/uco/core/",
    "uco-observable": "https://ontology.unifiedcyberontology.org/uco/observable/",
    "uco-types": "https://ontology.unifiedcyberontology.org/uco/types/",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "acme": "http://example.org/custom-ns#"
  },
  "@graph": [
    {
      "@id": "kb:windowsevent-38f71649-57d4-438e-9731-4e869eb3f3cb",
      "@type": "uco-observable:WindowsEvent",
      "uco-core:hasFacet": [
        {
          "@id": "kb:facet-7deeb420-2794-47e7-b4ed-d3f1ad478f2a",
          "@type": [
            "acme:WindowsLogonFacet",
            "uco-core:Facet"
          ],
          "acme:eventID": 4624,
          "acme:eventRecordID": 22232,
          "acme:eventDescription": "An account was successfully logged on.",
          "acme:logonType": 2,
          "uco-observable:observableCreatedTime": {
            "@type": "xsd:dateTime",
            "@value": "2019-08-15T17:10:12.591Z"
          }
        }
      ]
    },
    {
      "@id": "kb:accountsubject-e34b6992-3344-4133-8492-9bb26909e100",
      "@type": "uco-observable:Account",
      "uco-core:hasFacet": [
        {
          "@id": "kb:facet-6ce80c94-7a7d-4b1c-9cfc-2b7e0e118dab",
          "@type": [
            "acme:WindowsAccountFacet",
            "uco-core:Facet"
          ],
          "acme:accountLogin": "DESKTOP-QVUJ1JMS",
          "acme:domain": "WORKGROUP",
          "acme:sid": "S-1-5-18"
        }
      ]
    },
    {
      "@id": "kb:accounttarget-7e49de29-0c4d-4320-b142-f27b0fd27ef1",
      "@type": "uco-observable:Account",
      "uco-core:hasFacet": [
        {
          "@id": "kb:facet-a7a2c1b4-5ee2-4f6e-94d2-37cf4eaf79f6",
          "@type": [
            "acme:WindowsAccountFacet",
            "uco-core:Facet"
          ],
          "acme:accountLogin": "Selina",
          "acme:domain": "DESKTOP-QVUJ1JM",
          "acme:sid": "S-1-5-21-1114605987-1307930109-1710479394-1001"
        }
      ]
    },
    {
      "@id": "kb:relationship-subject-7982a445-5085-4707-b3cd-5083706c7541",
      "@type": "uco-observable:ObservableRelationship",
      "uco-core:source": { "@id": "kb:windowsevent-38f71649-57d4-438e-9731-4e869eb3f3cb" },
      "uco-core:target": { "@id": "kb:accountsubject-e34b6992-3344-4133-8492-9bb26909e100" },
      "uco-core:kindOfRelationship": "Subject_Account",
      "uco-core:isDirectional": true
    },
    {
      "@id": "kb:relationship-target-224e2ce3-81cd-4999-a456-d4c42895c2f0",
      "@type": "uco-observable:ObservableRelationship",
      "uco-core:source": { "@id": "kb:windowsevent-38f71649-57d4-438e-9731-4e869eb3f3cb" },
      "uco-core:target": { "@id": "kb:accounttarget-7e49de29-0c4d-4320-b142-f27b0fd27ef1" },
      "uco-core:kindOfRelationship": "Target_Account",
      "uco-core:isDirectional": true
    }
  ]
}

