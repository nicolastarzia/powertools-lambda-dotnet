# Powertools for AWS Lambda (.NET) - Data Masking

The Data Masking utility protects sensitive data (PII, credentials, financial records) before it is
logged, stored, or forwarded to another service, helping to meet requirements such as GDPR, HIPAA,
and PCI-DSS.

> **Status:** this package currently ships **Phase 1 – `Erase`** (irreversible masking). Field-level
> and full-payload encryption/decryption through a pluggable provider (AWS Encryption SDK + KMS) are
> planned for later phases. See [issue #1257](https://github.com/aws-powertools/powertools-lambda-dotnet/issues/1257).

## Key features

- Irreversibly **erase** sensitive fields while keeping the surrounding payload structure intact
- Select fields with simple dotted paths (for example `address.street`)
- Customizable masking: fixed string, length-preserving mask, or regex + replacement
- Trimming/Native AOT friendly when operating over JSON strings or `JsonNode`

## Erase

```csharp
using AWS.Lambda.Powertools.DataMasking;

var masker = new DataMasking();

string json = """
{
  "email": "john@example.com",
  "address": { "street": "123 Main St", "city": "Anytown" },
  "customer": { "ssn": "123-45-6789" }
}
""";

// Mask specific fields; the rest of the payload stays readable
string masked = masker.Erase(json, fields: new[] { "email", "address.street", "customer.ssn" });
// {
//   "email": "*****",
//   "address": { "street": "*****", "city": "Anytown" },
//   "customer": { "ssn": "*****" }
// }
```

### Custom masking

```csharp
// Length-preserving mask: "secret" -> "******"
masker.Erase(json, new[] { "password" }, new MaskingOptions { PreserveLength = true });

// Fixed replacement string
masker.Erase(json, new[] { "token" }, new MaskingOptions { MaskValue = "[REDACTED]" });

// Regex + replacement (keeps the first character of an email local part)
masker.Erase(json, new[] { "email" }, new MaskingOptions
{
    Pattern = new System.Text.RegularExpressions.Regex(@"^(.).*@"),
    Replacement = "$1****@"
});
```

### AOT / trimming

The `Erase(string, ...)` and `Erase(JsonNode, ...)` overloads are fully trimming/AOT safe. The
`Erase(object, ...)` overload uses reflection-based serialization and is annotated accordingly; for
AOT scenarios use the overload that accepts a source-generated `JsonTypeInfo`.
