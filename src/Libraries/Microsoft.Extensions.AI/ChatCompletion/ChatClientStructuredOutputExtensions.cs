﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Shared.Diagnostics;

#pragma warning disable SA1118 // Parameter should not span multiple lines

namespace Microsoft.Extensions.AI;

/// <summary>
/// Provides extension methods on <see cref="IChatClient"/> that simplify working with structured output.
/// </summary>
public static class ChatClientStructuredOutputExtensions
{
    private static readonly AIJsonSchemaCreateOptions _inferenceOptions = new()
    {
        IncludeSchemaKeyword = true,
        DisallowAdditionalProperties = true,
        IncludeTypeInEnumSchemas = true
    };

    /// <summary>Sends chat messages, requesting a response matching the type <typeparamref name="T"/>.</summary>
    /// <param name="chatClient">The <see cref="IChatClient"/>.</param>
    /// <param name="messages">The chat content to send.</param>
    /// <param name="options">The chat options to configure the request.</param>
    /// <param name="useJsonSchema">
    /// Optionally specifies whether to set a JSON schema on the <see cref="ChatResponseFormat"/>.
    /// This improves reliability if the underlying model supports native structured output with a schema, but may cause an error if the model does not support it.
    /// If not specified, the default value is <see langword="true" />.
    /// </param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> to monitor for cancellation requests. The default is <see cref="CancellationToken.None"/>.</param>
    /// <returns>The response messages generated by the client.</returns>
    /// <typeparam name="T">The type of structured output to request.</typeparam>
    public static Task<ChatResponse<T>> GetResponseAsync<T>(
        this IChatClient chatClient,
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        bool? useJsonSchema = null,
        CancellationToken cancellationToken = default) =>
        GetResponseAsync<T>(chatClient, messages, AIJsonUtilities.DefaultOptions, options, useJsonSchema, cancellationToken);

    /// <summary>Sends a user chat text message, requesting a response matching the type <typeparamref name="T"/>.</summary>
    /// <param name="chatClient">The <see cref="IChatClient"/>.</param>
    /// <param name="chatMessage">The text content for the chat message to send.</param>
    /// <param name="options">The chat options to configure the request.</param>
    /// <param name="useJsonSchema">
    /// Optionally specifies whether to set a JSON schema on the <see cref="ChatResponseFormat"/>.
    /// This improves reliability if the underlying model supports native structured output with a schema, but may cause an error if the model does not support it.
    /// If not specified, the default value is determined by the implementation.
    /// If a specific value is required, it must be specified by the caller.
    /// </param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> to monitor for cancellation requests. The default is <see cref="CancellationToken.None"/>.</param>
    /// <returns>The response messages generated by the client.</returns>
    /// <typeparam name="T">The type of structured output to request.</typeparam>
    public static Task<ChatResponse<T>> GetResponseAsync<T>(
        this IChatClient chatClient,
        string chatMessage,
        ChatOptions? options = null,
        bool? useJsonSchema = null,
        CancellationToken cancellationToken = default) =>
        GetResponseAsync<T>(chatClient, new ChatMessage(ChatRole.User, chatMessage), options, useJsonSchema, cancellationToken);

    /// <summary>Sends a chat message, requesting a response matching the type <typeparamref name="T"/>.</summary>
    /// <param name="chatClient">The <see cref="IChatClient"/>.</param>
    /// <param name="chatMessage">The chat message to send.</param>
    /// <param name="options">The chat options to configure the request.</param>
    /// <param name="useJsonSchema">
    /// Optionally specifies whether to set a JSON schema on the <see cref="ChatResponseFormat"/>.
    /// This improves reliability if the underlying model supports native structured output with a schema, but may cause an error if the model does not support it.
    /// If not specified, the default value is <see langword="true" />.
    /// </param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> to monitor for cancellation requests. The default is <see cref="CancellationToken.None"/>.</param>
    /// <returns>The response messages generated by the client.</returns>
    /// <typeparam name="T">The type of structured output to request.</typeparam>
    public static Task<ChatResponse<T>> GetResponseAsync<T>(
        this IChatClient chatClient,
        ChatMessage chatMessage,
        ChatOptions? options = null,
        bool? useJsonSchema = null,
        CancellationToken cancellationToken = default) =>
        GetResponseAsync<T>(chatClient, [chatMessage], options, useJsonSchema, cancellationToken);

    /// <summary>Sends a user chat text message, requesting a response matching the type <typeparamref name="T"/>.</summary>
    /// <param name="chatClient">The <see cref="IChatClient"/>.</param>
    /// <param name="chatMessage">The text content for the chat message to send.</param>
    /// <param name="serializerOptions">The JSON serialization options to use.</param>
    /// <param name="options">The chat options to configure the request.</param>
    /// <param name="useJsonSchema">
    /// Optionally specifies whether to set a JSON schema on the <see cref="ChatResponseFormat"/>.
    /// This improves reliability if the underlying model supports native structured output with a schema, but may cause an error if the model does not support it.
    /// If not specified, the default value is <see langword="true" />.
    /// </param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> to monitor for cancellation requests. The default is <see cref="CancellationToken.None"/>.</param>
    /// <returns>The response messages generated by the client.</returns>
    /// <typeparam name="T">The type of structured output to request.</typeparam>
    public static Task<ChatResponse<T>> GetResponseAsync<T>(
        this IChatClient chatClient,
        string chatMessage,
        JsonSerializerOptions serializerOptions,
        ChatOptions? options = null,
        bool? useJsonSchema = null,
        CancellationToken cancellationToken = default) =>
        GetResponseAsync<T>(chatClient, new ChatMessage(ChatRole.User, chatMessage), serializerOptions, options, useJsonSchema, cancellationToken);

    /// <summary>Sends a chat message, requesting a response matching the type <typeparamref name="T"/>.</summary>
    /// <param name="chatClient">The <see cref="IChatClient"/>.</param>
    /// <param name="chatMessage">The chat message to send.</param>
    /// <param name="serializerOptions">The JSON serialization options to use.</param>
    /// <param name="options">The chat options to configure the request.</param>
    /// <param name="useJsonSchema">
    /// Optionally specifies whether to set a JSON schema on the <see cref="ChatResponseFormat"/>.
    /// This improves reliability if the underlying model supports native structured output with a schema, but may cause an error if the model does not support it.
    /// If not specified, the default value is <see langword="true" />.
    /// </param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> to monitor for cancellation requests. The default is <see cref="CancellationToken.None"/>.</param>
    /// <returns>The response messages generated by the client.</returns>
    /// <typeparam name="T">The type of structured output to request.</typeparam>
    public static Task<ChatResponse<T>> GetResponseAsync<T>(
        this IChatClient chatClient,
        ChatMessage chatMessage,
        JsonSerializerOptions serializerOptions,
        ChatOptions? options = null,
        bool? useJsonSchema = null,
        CancellationToken cancellationToken = default) =>
        GetResponseAsync<T>(chatClient, [chatMessage], serializerOptions, options, useJsonSchema, cancellationToken);

    /// <summary>Sends chat messages, requesting a response matching the type <typeparamref name="T"/>.</summary>
    /// <param name="chatClient">The <see cref="IChatClient"/>.</param>
    /// <param name="messages">The chat content to send.</param>
    /// <param name="serializerOptions">The JSON serialization options to use.</param>
    /// <param name="options">The chat options to configure the request.</param>
    /// <param name="useJsonSchema">
    /// Optionally specifies whether to set a JSON schema on the <see cref="ChatResponseFormat"/>.
    /// This improves reliability if the underlying model supports native structured output with a schema, but may cause an error if the model does not support it.
    /// If not specified, the default value is <see langword="true" />.
    /// </param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> to monitor for cancellation requests. The default is <see cref="CancellationToken.None"/>.</param>
    /// <returns>The response messages generated by the client.</returns>
    /// <typeparam name="T">The type of structured output to request.</typeparam>
    /// <exception cref="ArgumentNullException"><paramref name="chatClient"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="messages"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="serializerOptions"/> is <see langword="null"/>.</exception>
    public static async Task<ChatResponse<T>> GetResponseAsync<T>(
        this IChatClient chatClient,
        IEnumerable<ChatMessage> messages,
        JsonSerializerOptions serializerOptions,
        ChatOptions? options = null,
        bool? useJsonSchema = null,
        CancellationToken cancellationToken = default)
    {
        _ = Throw.IfNull(chatClient);
        _ = Throw.IfNull(messages);
        _ = Throw.IfNull(serializerOptions);

        serializerOptions.MakeReadOnly();

        var schemaElement = AIJsonUtilities.CreateJsonSchema(
            type: typeof(T),
            serializerOptions: serializerOptions,
            inferenceOptions: _inferenceOptions);

        bool isWrappedInObject;
        JsonElement schema;
        if (SchemaRepresentsObject(schemaElement))
        {
            // For object-representing schemas, we can use them as-is
            isWrappedInObject = false;
            schema = schemaElement;
        }
        else
        {
            // For non-object-representing schemas, we wrap them in an object schema, because all
            // the real LLM providers today require an object schema as the root. This is currently
            // true even for providers that support native structured output.
            isWrappedInObject = true;
            schema = JsonSerializer.SerializeToElement(new JsonObject
            {
                { "$schema", "https://json-schema.org/draft/2020-12/schema" },
                { "type", "object" },
                { "properties", new JsonObject { { "data", JsonElementToJsonNode(schemaElement) } } },
                { "additionalProperties", false },
                { "required", new JsonArray("data") },
            }, AIJsonUtilities.DefaultOptions.GetTypeInfo(typeof(JsonObject)));
        }

        ChatMessage? promptAugmentation = null;
        options = options is not null ? options.Clone() : new();

        // We default to assuming that models support JSON schema because developers will normally use
        // GetResponseAsync<T> only with models that do. If the model doesn't support JSON schema, it may
        // throw or it may ignore the schema. In these cases developers should pass useJsonSchema: false.
        if (useJsonSchema.GetValueOrDefault(true))
        {
            // When using native structured output, we don't add any additional prompt, because
            // the LLM backend is meant to do whatever's needed to explain the schema to the LLM.
            options.ResponseFormat = ChatResponseFormat.ForJsonSchema(
                schema,
                schemaName: AIFunctionFactory.SanitizeMemberName(typeof(T).Name),
                schemaDescription: typeof(T).GetCustomAttribute<DescriptionAttribute>()?.Description);
        }
        else
        {
            options.ResponseFormat = ChatResponseFormat.Json;

            // When not using native JSON schema, augment the chat messages with a schema prompt
            promptAugmentation = new ChatMessage(ChatRole.User, $$"""
                Respond with a JSON value conforming to the following schema:
                ```
                {{schema}}
                ```
                """);

            messages = [.. messages, promptAugmentation];
        }

        var result = await chatClient.GetResponseAsync(messages, options, cancellationToken).ConfigureAwait(false);
        return new ChatResponse<T>(result, serializerOptions) { IsWrappedInObject = isWrappedInObject };
    }

    private static bool SchemaRepresentsObject(JsonElement schemaElement)
    {
        if (schemaElement.ValueKind is JsonValueKind.Object)
        {
            foreach (var property in schemaElement.EnumerateObject())
            {
                if (property.NameEquals("type"u8))
                {
                    return property.Value.ValueKind == JsonValueKind.String
                        && property.Value.ValueEquals("object"u8);
                }
            }
        }

        return false;
    }

    private static JsonNode? JsonElementToJsonNode(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.Null => null,
            JsonValueKind.Array => JsonArray.Create(element),
            JsonValueKind.Object => JsonObject.Create(element),
            _ => JsonValue.Create(element)
        };
    }
}
