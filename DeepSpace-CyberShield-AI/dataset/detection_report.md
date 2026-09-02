# DeepSpace CyberShield AI — Detection Report

- Total records analyzed: **1230**
- Accuracy: **85.61%**
- Precision: **100.0%**
- Recall: **60.67%**
- F1-Score: **75.52%**

## Confusion Matrix

| | Predicted Legitimate | Predicted Malicious |
|---|---|---|
| Actual Legitimate | 780 | 0 |
| Actual Malicious (TTL Decayed) | 177 | 273 |

## Verdicts by Attack Type

- **Bundle Flooding** → Legitimate: 76, Malicious (TTL Decayed): 0, Suspicious: 14
- **Normal** → Legitimate: 780, Malicious (TTL Decayed): 0, Suspicious: 0
- **Relay Tampering** → Legitimate: 13, Malicious (TTL Decayed): 15, Suspicious: 62
- **Replay** → Legitimate: 0, Malicious (TTL Decayed): 76, Suspicious: 14
- **Spoofing** → Legitimate: 88, Malicious (TTL Decayed): 0, Suspicious: 2
- **Unauthorized Injection** → Legitimate: 0, Malicious (TTL Decayed): 90, Suspicious: 0