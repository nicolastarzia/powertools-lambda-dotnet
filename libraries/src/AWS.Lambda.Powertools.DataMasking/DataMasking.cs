/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

using System;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;
using AWS.Lambda.Powertools.DataMasking.Internal;

namespace AWS.Lambda.Powertools.DataMasking;

/// <summary>
/// Provides irreversible masking (erasing) of sensitive fields within a payload.
/// </summary>
/// <remarks>
/// This is Phase 1 of the Data Masking utility and covers <c>Erase</c> only. Field-level and
/// full-payload encryption/decryption via a pluggable provider are planned for later phases.
/// Field selection uses simple dotted paths (for example <c>"address.street"</c>).
/// </remarks>
public sealed class DataMasking
{
    /// <summary>
    /// Irreversibly masks the supplied fields within a JSON string.
    /// This overload is fully trimming/AOT safe.
    /// </summary>
    /// <param name="json">The JSON payload as a string.</param>
    /// <param name="fields">The dotted field paths to mask (for example <c>"customer.ssn"</c>).</param>
    /// <param name="options">Optional masking options. Defaults to a fixed <c>*****</c> mask.</param>
    /// <returns>The masked payload serialized back to a JSON string.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="json"/> or <paramref name="fields"/> is <see langword="null"/>.</exception>
    public string Erase(string json, string[] fields, MaskingOptions? options = null)
    {
        if (json is null) throw new ArgumentNullException(nameof(json));
        if (fields is null) throw new ArgumentNullException(nameof(fields));

        var root = JsonNode.Parse(json);
        JsonNodeMasker.MaskFields(root, fields, options ?? MaskingOptions.Default);
        return root?.ToJsonString() ?? "null";
    }

    /// <summary>
    /// Irreversibly masks the supplied fields within a <see cref="JsonNode"/>, mutating it in place.
    /// This overload is fully trimming/AOT safe.
    /// </summary>
    /// <param name="node">The payload as a <see cref="JsonNode"/>. Masked in place.</param>
    /// <param name="fields">The dotted field paths to mask.</param>
    /// <param name="options">Optional masking options. Defaults to a fixed <c>*****</c> mask.</param>
    /// <returns>The same <paramref name="node"/> instance, masked in place.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="node"/> or <paramref name="fields"/> is <see langword="null"/>.</exception>
    public JsonNode Erase(JsonNode node, string[] fields, MaskingOptions? options = null)
    {
        if (node is null) throw new ArgumentNullException(nameof(node));
        if (fields is null) throw new ArgumentNullException(nameof(fields));

        JsonNodeMasker.MaskFields(node, fields, options ?? MaskingOptions.Default);
        return node;
    }

    /// <summary>
    /// Irreversibly masks the supplied fields within an object, returning the masked payload as a JSON string.
    /// </summary>
    /// <remarks>
    /// This overload serializes <paramref name="data"/> using reflection-based
    /// <see cref="System.Text.Json"/> and is therefore not compatible with trimming/Native AOT.
    /// For AOT scenarios use <see cref="Erase(string,string[],MaskingOptions)"/>,
    /// <see cref="Erase(JsonNode,string[],MaskingOptions)"/>, or
    /// <see cref="Erase(object,JsonTypeInfo,string[],MaskingOptions)"/> with a source-generated context.
    /// </remarks>
    /// <param name="data">The object to mask.</param>
    /// <param name="fields">The dotted field paths to mask.</param>
    /// <param name="options">Optional masking options. Defaults to a fixed <c>*****</c> mask.</param>
    /// <returns>The masked payload serialized to a JSON string.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="data"/> or <paramref name="fields"/> is <see langword="null"/>.</exception>
    [RequiresUnreferencedCode("JSON serialization of the supplied object might require types that cannot be statically analyzed. Use an overload that accepts a JsonTypeInfo for trimming/AOT scenarios.")]
    [RequiresDynamicCode("JSON serialization of the supplied object might require runtime code generation. Use an overload that accepts a JsonTypeInfo for trimming/AOT scenarios.")]
    public string Erase(object data, string[] fields, MaskingOptions? options = null)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (fields is null) throw new ArgumentNullException(nameof(fields));

        var root = JsonSerializer.SerializeToNode(data);
        JsonNodeMasker.MaskFields(root, fields, options ?? MaskingOptions.Default);
        return root?.ToJsonString() ?? "null";
    }

    /// <summary>
    /// Irreversibly masks the supplied fields within an object using a source-generated
    /// <see cref="JsonTypeInfo"/>, returning the masked payload as a JSON string.
    /// This overload is trimming/AOT safe when supplied with a source-generated type info.
    /// </summary>
    /// <param name="data">The object to mask.</param>
    /// <param name="jsonTypeInfo">The source-generated type metadata used to serialize <paramref name="data"/>.</param>
    /// <param name="fields">The dotted field paths to mask.</param>
    /// <param name="options">Optional masking options. Defaults to a fixed <c>*****</c> mask.</param>
    /// <returns>The masked payload serialized to a JSON string.</returns>
    /// <exception cref="ArgumentNullException">A required argument is <see langword="null"/>.</exception>
    public string Erase(object data, JsonTypeInfo jsonTypeInfo, string[] fields, MaskingOptions? options = null)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (jsonTypeInfo is null) throw new ArgumentNullException(nameof(jsonTypeInfo));
        if (fields is null) throw new ArgumentNullException(nameof(fields));

        var root = JsonSerializer.SerializeToNode(data, jsonTypeInfo);
        JsonNodeMasker.MaskFields(root, fields, options ?? MaskingOptions.Default);
        return root?.ToJsonString() ?? "null";
    }
}
