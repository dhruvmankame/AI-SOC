/* Snapshot extracted from AI-SOC/data/cicids_seed.sql; not live telemetry. */
export const snapshot = {
  "incidents": [
    {
      "id": "9e8dcd11-a725-51ac-b7fc-3aa88ec8792b",
      "code": "INC-2017-0001",
      "title": "SSH/FTP brute-force credential attack",
      "risk": 96.0,
      "mitre": "T1110",
      "status": "open"
    },
    {
      "id": "dd89374b-f4f8-534a-a645-284e36984582",
      "code": "INC-2017-0002",
      "title": "Volumetric HTTP DDoS flood",
      "risk": 96.0,
      "mitre": "T1498",
      "status": "open"
    },
    {
      "id": "42fb54b7-8047-58a3-8da0-295cd41f1946",
      "code": "INC-2017-0003",
      "title": "Ares botnet C2 beaconing",
      "risk": 96.0,
      "mitre": "T1071",
      "status": "open"
    }
  ],
  "alerts": [
    {
      "id": "8b280b6f-e1ca-50d8-806a-51a0435f526d",
      "title": "SSH/FTP brute-force credential attack",
      "severity": "high",
      "confidence": 0.999,
      "detector": "R-NET-FLOOD",
      "contributions": {
        "R-NET-BRUTEFORCE": 0.95,
        "R-NET-FLOOD": 0.97,
        "flow_rate_zscore": 0.593
      },
      "entity": "172.16.0.1",
      "eventIds": [
        "e8ec570c-bd1a-5158-bca0-f43d263ad966",
        "498cbb9a-a031-5c75-a7b1-0f0add331dc1",
        "f9896f0c-c9cd-5f23-a4a2-ec550fc2a905",
        "84b7d03f-06e6-55c6-a3ac-bb24bf8ce19e",
        "27033f73-6367-5cfe-aee2-ea16fc4ddc3b",
        "c2304c9b-ef9e-5da2-96b5-95486af0bc34",
        "ecdec1af-661f-558a-b0f4-a341c23619ba",
        "5ad802db-5b0e-59a6-bdbe-7f2ae0e2842b"
      ],
      "correlations": 13834,
      "status": "new",
      "incidentId": "9e8dcd11-a725-51ac-b7fc-3aa88ec8792b"
    },
    {
      "id": "cbaada43-40b4-5f84-9e2e-7d9bb4abf5ec",
      "title": "Volumetric HTTP DDoS flood",
      "severity": "high",
      "confidence": 0.97,
      "detector": "R-NET-FLOOD",
      "contributions": {
        "R-NET-FLOOD": 0.97
      },
      "entity": "172.16.0.1",
      "eventIds": [
        "7a2b436d-8d6b-572f-9578-5640f34eb6bd",
        "51251662-04e8-5b93-9662-b677d87f1b86",
        "493a716b-c910-5605-a049-206347a18da0",
        "bef1752a-5be3-5941-a7ac-898b4087cae5",
        "a4210b81-b740-5f9f-8d97-1c3f171eefe7",
        "1f57263f-c426-530c-893b-e5ad025622d2",
        "c6674432-ef8d-5e6b-abda-8ad4bfae4e25",
        "c9760e28-5dea-5873-8586-dd0355536381"
      ],
      "correlations": 128024,
      "status": "new",
      "incidentId": "dd89374b-f4f8-534a-a645-284e36984582"
    },
    {
      "id": "15d6e6aa-d3dd-5bd4-b0da-2e0f986f9c44",
      "title": "Ares botnet C2 beaconing",
      "severity": "high",
      "confidence": 0.85,
      "detector": "R-NET-BEACON",
      "contributions": {
        "R-NET-BEACON": 0.85
      },
      "entity": "205.174.165.73",
      "eventIds": [
        "be521d5c-ca44-580a-a9b6-251356af19a3",
        "4f42affc-7725-53c8-9315-b9fc48985761",
        "b8847ea8-fd26-5ebe-b307-df67dd4cd8a5",
        "7b3c29e8-7d52-532f-a9da-9a87a18e6dd0",
        "38a11ef5-0eb5-572f-9115-a1692aca68df",
        "39ab7228-04e5-5c26-8fa1-155a357e7268",
        "8cd27fc7-bce2-508b-9eb6-8893123e8a7a",
        "6d2881a1-eed5-5d58-9216-42f1fc4374c9"
      ],
      "correlations": 1257,
      "status": "new",
      "incidentId": "42fb54b7-8047-58a3-8da0-295cd41f1946"
    }
  ],
  "entities": [
    {
      "incidentId": "9e8dcd11-a725-51ac-b7fc-3aa88ec8792b",
      "type": "ip",
      "value": "172.16.0.1",
      "role": "actor"
    },
    {
      "incidentId": "9e8dcd11-a725-51ac-b7fc-3aa88ec8792b",
      "type": "ip",
      "value": "192.168.10.50",
      "role": "target"
    },
    {
      "incidentId": "dd89374b-f4f8-534a-a645-284e36984582",
      "type": "ip",
      "value": "172.16.0.1",
      "role": "actor"
    },
    {
      "incidentId": "dd89374b-f4f8-534a-a645-284e36984582",
      "type": "ip",
      "value": "192.168.10.50",
      "role": "target"
    },
    {
      "incidentId": "42fb54b7-8047-58a3-8da0-295cd41f1946",
      "type": "ip",
      "value": "205.174.165.73",
      "role": "actor"
    },
    {
      "incidentId": "42fb54b7-8047-58a3-8da0-295cd41f1946",
      "type": "ip",
      "value": "192.168.10.14",
      "role": "victim"
    },
    {
      "incidentId": "42fb54b7-8047-58a3-8da0-295cd41f1946",
      "type": "ip",
      "value": "192.168.10.15",
      "role": "victim"
    },
    {
      "incidentId": "42fb54b7-8047-58a3-8da0-295cd41f1946",
      "type": "ip",
      "value": "192.168.10.5",
      "role": "victim"
    },
    {
      "incidentId": "42fb54b7-8047-58a3-8da0-295cd41f1946",
      "type": "ip",
      "value": "192.168.10.8",
      "role": "victim"
    },
    {
      "incidentId": "42fb54b7-8047-58a3-8da0-295cd41f1946",
      "type": "ip",
      "value": "192.168.10.9",
      "role": "victim"
    }
  ],
  "metrics": {
    "events": 4800,
    "signals": 2488,
    "alerts": 3,
    "incidents": 3,
    "rules": 4
  },
  "severity": [
    {
      "name": "high",
      "count": 1772
    },
    {
      "name": "info",
      "count": 3022
    },
    {
      "name": "medium",
      "count": 6
    }
  ],
  "sources": [
    {
      "name": "network",
      "count": 4800
    }
  ],
  "volume": [
    {
      "hour": "2017-07-04 01:00",
      "count": 74
    },
    {
      "hour": "2017-07-04 02:00",
      "count": 149
    },
    {
      "hour": "2017-07-04 03:00",
      "count": 95
    },
    {
      "hour": "2017-07-04 04:00",
      "count": 127
    },
    {
      "hour": "2017-07-04 05:00",
      "count": 1
    },
    {
      "hour": "2017-07-04 08:00",
      "count": 4
    },
    {
      "hour": "2017-07-04 09:00",
      "count": 169
    },
    {
      "hour": "2017-07-04 10:00",
      "count": 827
    },
    {
      "hour": "2017-07-04 11:00",
      "count": 117
    },
    {
      "hour": "2017-07-04 12:00",
      "count": 37
    },
    {
      "hour": "2017-07-07 03:00",
      "count": 965
    },
    {
      "hour": "2017-07-07 04:00",
      "count": 625
    },
    {
      "hour": "2017-07-07 05:00",
      "count": 10
    },
    {
      "hour": "2017-07-07 09:00",
      "count": 240
    },
    {
      "hour": "2017-07-07 10:00",
      "count": 1031
    },
    {
      "hour": "2017-07-07 11:00",
      "count": 263
    },
    {
      "hour": "2017-07-07 12:00",
      "count": 66
    }
  ]
} as const;
