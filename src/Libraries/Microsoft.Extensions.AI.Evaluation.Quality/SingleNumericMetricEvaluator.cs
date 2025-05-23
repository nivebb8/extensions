﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Shared.Diagnostics;

namespace Microsoft.Extensions.AI.Evaluation.Quality;

/// <summary>
/// An <see langword="abstract"/> base class that can be used to implement an AI-based <see cref="IEvaluator"/> that
/// produces an <see cref="EvaluationResult"/> containing a single <see cref="NumericMetric"/>.
/// </summary>
public abstract class SingleNumericMetricEvaluator : ChatConversationEvaluator
{
    /// <inheritdoc/>
    public sealed override IReadOnlyCollection<string> EvaluationMetricNames => [MetricName];

    /// <summary>
    /// Gets the <see cref="EvaluationMetric.Name"/> of the <see cref="NumericMetric"/> produced by this
    /// <see cref="IEvaluator"/>.
    /// </summary>
    protected abstract string MetricName { get; }

    /// <inheritdoc/>
    protected sealed override string? SystemPrompt =>
        $"""
        You are an AI assistant. You will be given the definition of an evaluation metric for assessing the quality of
        a response in a question-answering task. Your job is to compute an accurate evaluation score for the provided
        evaluation metric based on the provided scoring guidance.

        This evaluation score should always be an integer between 1 and 5. So your response should be 1 or 2 or 3 or 4
        or 5.

        Your response should be a single character containing only the evaluation score. Do not include any other text
        in your response besides the evaluation score.
        """;

    private readonly ChatOptions _chatOptions =
        new ChatOptions
        {
            MaxOutputTokens = 1,
            Temperature = 0.0f,
            TopP = 1.0f,
            PresencePenalty = 0.0f,
            FrequencyPenalty = 0.0f,
            ResponseFormat = ChatResponseFormat.Text
        };

    /// <inheritdoc/>
    protected sealed override EvaluationResult InitializeResult()
    {
        var metric = new NumericMetric(MetricName);
        return new EvaluationResult(metric);
    }

    /// <inheritdoc/>
    protected sealed override async ValueTask PerformEvaluationAsync(
        ChatConfiguration chatConfiguration,
        IList<ChatMessage> evaluationMessages,
        EvaluationResult result,
        CancellationToken cancellationToken)
    {
        _ = Throw.IfNull(chatConfiguration);
        _ = Throw.IfNull(result);

        Stopwatch stopwatch = Stopwatch.StartNew();
        NumericMetric metric = result.Get<NumericMetric>(MetricName);

        try
        {
            ChatResponse evaluationResponse =
                await chatConfiguration.ChatClient.GetResponseAsync(
                    evaluationMessages,
                    _chatOptions,
                    cancellationToken: cancellationToken).ConfigureAwait(false);

            if (!string.IsNullOrWhiteSpace(evaluationResponse.ModelId))
            {
                metric.AddOrUpdateMetadata(name: "evaluation-model-used", value: evaluationResponse.ModelId!);
            }

            if (evaluationResponse.Usage is UsageDetails usage)
            {
                if (usage.InputTokenCount is not null)
                {
                    metric.AddOrUpdateMetadata(name: "evaluation-input-tokens-used", value: $"{usage.InputTokenCount}");
                }

                if (usage.OutputTokenCount is not null)
                {
                    metric.AddOrUpdateMetadata(name: "evaluation-output-tokens-used", value: $"{usage.OutputTokenCount}");
                }

                if (usage.TotalTokenCount is not null)
                {
                    metric.AddOrUpdateMetadata(name: "evaluation-total-tokens-used", value: $"{usage.TotalTokenCount}");
                }
            }

            string evaluationResponseText = evaluationResponse.Text.Trim();

            if (string.IsNullOrEmpty(evaluationResponseText))
            {
                metric.AddDiagnostics(
                    EvaluationDiagnostic.Error(
                        "Evaluation failed because the model failed to produce a valid evaluation response."));
            }
            else if (int.TryParse(evaluationResponseText, out int score))
            {
                metric.Value = score;
            }
            else
            {
                metric.AddDiagnostics(
                    EvaluationDiagnostic.Error(
                        $"Failed to parse '{evaluationResponseText!}' as an integer score for '{MetricName}'."));
            }

            metric.Interpretation = metric.InterpretScore();
        }
        finally
        {
            stopwatch.Stop();
            string duration = $"{stopwatch.Elapsed.TotalSeconds.ToString("F2", CultureInfo.InvariantCulture)} s";
            metric.AddOrUpdateMetadata(name: "evaluation-duration", value: duration);
        }
    }
}
