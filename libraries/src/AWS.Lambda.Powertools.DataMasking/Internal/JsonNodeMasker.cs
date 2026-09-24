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
using System.Collections.Generic;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace AWS.Lambda.Powertools.DataMasking.Internal;

/// <summary>
/// Applies masking to fields within a <see cref="JsonNode"/> tree using simple dotted field paths
/// (for example <c>"address.street"</c>).
/// </summary>
/// <remarks>
/// This intentionally operates on the <see cref="System.Text.Json.Nodes"/> object model rather than
/// reflecting over arbitrary CLR types, which keeps the operation trimming/AOT friendly.
/// Full JMESPath expression support (wildcards, filters) is planned for a later phase.
/// </remarks>
internal static class JsonNodeMasker
{
    private const char PathSeparator = '.';

    /// <summary>
    /// Masks every supplied field path within <paramref name="root"/> in place.
    /// </summary>
    /// <param name="root">The root node of the payload being masked.</param>
    /// <param name="fields">The dotted field paths to mask.</param>
    /// <param name="options">The masking options controlling the replacement.</param>
    internal static void MaskFields(JsonNode? root, IEnumerable<string> fields, MaskingOptions options)
    {
        if (root is null)
        {
            return;
        }

        foreach (var field in fields)
        {
            if (string.IsNullOrWhiteSpace(field))
            {
                continue;
            }

            MaskPath(root, field, options);
        }
    }

    private static void MaskPath(JsonNode root, string path, MaskingOptions options)
    {
        // Walk the dotted path segment-by-segment without allocating the intermediate string[]
        // that string.Split would produce. JsonObject lookups require a string key, so each
        // segment is still materialized, but the array (and its bounds/GC overhead) is avoided.
        var current = root;
        var start = 0;

        int separator;
        while ((separator = path.IndexOf(PathSeparator, start)) >= 0)
        {
            var segment = path.Substring(start, separator - start);

            // If any intermediate segment is missing or is not an object, the path does not
            // exist in this payload and is skipped.
            if (current is not JsonObject obj || !obj.TryGetPropertyValue(segment, out var next) || next is null)
            {
                return;
            }

            current = next;
            start = separator + 1;
        }

        if (current is JsonObject parent)
        {
            var leaf = start == 0 ? path : path.Substring(start);
            if (parent.ContainsKey(leaf))
            {
                parent[leaf] = MaskValue(parent[leaf], options);
            }
        }
    }

    private static JsonNode? MaskValue(JsonNode? value, MaskingOptions options)
    {
        // A null JSON value stays null; there is nothing sensitive to mask.
        if (value is null)
        {
            return null;
        }

        // The fixed-mask case (the default) ignores the original value, so avoid serializing
        // the (potentially large) subtree to a string just to discard it.
        if (!options.RequiresRawValue)
        {
            return JsonValue.Create(options.Apply(string.Empty));
        }

        var raw = value is JsonValue jsonValue ? jsonValue.ToString() : value.ToJsonString();
        return JsonValue.Create(options.Apply(raw));
    }

    /// <summary>
    /// Applies an asynchronous string transform (for example encrypt or decrypt) to each supplied
    /// field path within <paramref name="root"/>, in place. Missing paths are skipped.
    /// </summary>
    internal static async Task TransformFieldsAsync(
        JsonNode? root,
        IEnumerable<string> fields,
        Func<string, Task<string>> transform)
    {
        if (root is null)
        {
            return;
        }

        foreach (var field in fields)
        {
            if (string.IsNullOrWhiteSpace(field))
            {
                continue;
            }

            await TransformPathAsync(root, field, transform);
        }
    }

    private static async Task TransformPathAsync(JsonNode root, string path, Func<string, Task<string>> transform)
    {
        var current = root;
        var start = 0;

        int separator;
        while ((separator = path.IndexOf(PathSeparator, start)) >= 0)
        {
            var segment = path.Substring(start, separator - start);
            if (current is not JsonObject obj || !obj.TryGetPropertyValue(segment, out var next) || next is null)
            {
                return;
            }

            current = next;
            start = separator + 1;
        }

        if (current is JsonObject parent)
        {
            var leaf = start == 0 ? path : path.Substring(start);
            if (parent.ContainsKey(leaf) && parent[leaf] is not null)
            {
                var value = parent[leaf]!;
                var raw = value is JsonValue jsonValue ? jsonValue.ToString() : value.ToJsonString();
                var transformed = await transform(raw);
                parent[leaf] = JsonValue.Create(transformed);
            }
        }
    }
}
