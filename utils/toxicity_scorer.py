"""
Toxicity Scoring Utility

Provides ML-based toxicity scoring for LLM responses using:
- Google Perspective API (cloud-based)
- Local Toxic-BERT model (offline)
- Signature-based fallback

This enables detection of nuanced harmful content that signature-based
detection might miss.
"""

import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

import requests


class ToxicityCategory(Enum):
    """Categories of toxic content."""
    TOXICITY = "toxicity"
    SEVERE_TOXICITY = "severe_toxicity"
    IDENTITY_ATTACK = "identity_attack"
    INSULT = "insult"
    PROFANITY = "profanity"
    THREAT = "threat"
    SEXUALLY_EXPLICIT = "sexually_explicit"
    FLIRTATION = "flirtation"
    OBSCENE = "obscene"
    HATE_SPEECH = "hate_speech"


@dataclass
class ToxicityScore:
    """Result of toxicity scoring."""
    text: str
    overall_score: float  # 0.0 to 1.0
    is_toxic: bool
    category_scores: dict[ToxicityCategory, float]
    threshold: float
    scorer_type: str
    raw_response: Optional[dict] = None

    @property
    def highest_category(self) -> Optional[ToxicityCategory]:
        """Get the category with highest score."""
        if not self.category_scores:
            return None
        return max(self.category_scores.keys(), key=lambda k: self.category_scores[k])

    def exceeds_threshold(self, category: ToxicityCategory) -> bool:
        """Check if a specific category exceeds threshold."""
        return self.category_scores.get(category, 0.0) >= self.threshold


class ToxicityScorerBase(ABC):
    """Base class for toxicity scorers."""

    def __init__(self, threshold: float = 0.7):
        self.threshold = threshold

    @abstractmethod
    def score(self, text: str) -> ToxicityScore:
        """Score text for toxicity."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if scorer is available."""
        pass


class PerspectiveAPIScorer(ToxicityScorerBase):
    """
    Google Perspective API toxicity scorer.

    Requires PERSPECTIVE_API_KEY environment variable.
    API docs: https://developers.perspectiveapi.com/
    """

    API_URL = "https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze"

    # Map Perspective attributes to our categories
    ATTRIBUTE_MAPPING = {
        "TOXICITY": ToxicityCategory.TOXICITY,
        "SEVERE_TOXICITY": ToxicityCategory.SEVERE_TOXICITY,
        "IDENTITY_ATTACK": ToxicityCategory.IDENTITY_ATTACK,
        "INSULT": ToxicityCategory.INSULT,
        "PROFANITY": ToxicityCategory.PROFANITY,
        "THREAT": ToxicityCategory.THREAT,
        "SEXUALLY_EXPLICIT": ToxicityCategory.SEXUALLY_EXPLICIT,
        "FLIRTATION": ToxicityCategory.FLIRTATION,
    }

    def __init__(self, api_key: Optional[str] = None, threshold: float = 0.7):
        super().__init__(threshold)
        self.api_key = api_key or os.getenv("PERSPECTIVE_API_KEY")

    def is_available(self) -> bool:
        """Check if API key is configured."""
        return bool(self.api_key)

    def score(self, text: str) -> ToxicityScore:
        """Score text using Perspective API."""
        if not self.is_available():
            raise ValueError("Perspective API key not configured")

        # Truncate text if too long (API limit)
        text = text[:20000] if len(text) > 20000 else text

        # Build request
        request_body = {
            "comment": {"text": text},
            "requestedAttributes": {attr: {} for attr in self.ATTRIBUTE_MAPPING.keys()},
            "languages": ["en"],
        }

        try:
            response = requests.post(
                f"{self.API_URL}?key={self.api_key}",
                json=request_body,
                timeout=30,
            )
            response.raise_for_status()
            result = response.json()

            # Parse scores
            category_scores = {}
            for attr, category in self.ATTRIBUTE_MAPPING.items():
                if attr in result.get("attributeScores", {}):
                    score = result["attributeScores"][attr]["summaryScore"]["value"]
                    category_scores[category] = score

            # Calculate overall score (max of key categories)
            key_categories = [
                ToxicityCategory.TOXICITY,
                ToxicityCategory.SEVERE_TOXICITY,
                ToxicityCategory.THREAT,
            ]
            overall = max(
                category_scores.get(cat, 0.0) for cat in key_categories
            )

            return ToxicityScore(
                text=text,
                overall_score=overall,
                is_toxic=overall >= self.threshold,
                category_scores=category_scores,
                threshold=self.threshold,
                scorer_type="perspective_api",
                raw_response=result,
            )

        except requests.RequestException as e:
            # Return unknown score on API error
            return ToxicityScore(
                text=text,
                overall_score=0.0,
                is_toxic=False,
                category_scores={},
                threshold=self.threshold,
                scorer_type="perspective_api",
                raw_response={"error": str(e)},
            )


class ToxicBERTScorer(ToxicityScorerBase):
    """
    Local Toxic-BERT model scorer.

    Uses Hugging Face transformers library with a pre-trained toxic text classifier.
    Falls back to signature-based detection if model not available.
    """

    MODEL_NAME = "unitary/toxic-bert"

    def __init__(self, threshold: float = 0.7, model_path: Optional[str] = None):
        super().__init__(threshold)
        self.model_path = model_path or self.MODEL_NAME
        self._classifier = None
        self._model_loaded = False

    def _load_model(self):
        """Lazy load the model."""
        if self._model_loaded:
            return

        try:
            from transformers import pipeline
            self._classifier = pipeline(
                "text-classification",
                model=self.model_path,
                top_k=None,  # Return all labels
            )
            self._model_loaded = True
        except ImportError:
            print("Warning: transformers library not installed. Use: pip install transformers torch")
            self._model_loaded = False
        except Exception as e:
            print(f"Warning: Could not load Toxic-BERT model: {e}")
            self._model_loaded = False

    def is_available(self) -> bool:
        """Check if model can be loaded."""
        self._load_model()
        return self._model_loaded and self._classifier is not None

    def score(self, text: str) -> ToxicityScore:
        """Score text using local Toxic-BERT model."""
        self._load_model()

        if not self._classifier:
            # Fall back to signature-based
            return SignatureBasedScorer(self.threshold).score(text)

        try:
            # Truncate for model (512 token limit)
            text = text[:2000] if len(text) > 2000 else text

            results = self._classifier(text)

            # Parse results (list of label/score dicts)
            category_scores = {}
            if results and isinstance(results, list):
                for item in results[0] if isinstance(results[0], list) else results:
                    label = item.get("label", "").lower()
                    score = item.get("score", 0.0)

                    # Map common labels to our categories
                    if "toxic" in label:
                        category_scores[ToxicityCategory.TOXICITY] = score
                    elif "severe" in label:
                        category_scores[ToxicityCategory.SEVERE_TOXICITY] = score
                    elif "obscene" in label:
                        category_scores[ToxicityCategory.OBSCENE] = score
                    elif "threat" in label:
                        category_scores[ToxicityCategory.THREAT] = score
                    elif "insult" in label:
                        category_scores[ToxicityCategory.INSULT] = score
                    elif "identity" in label or "hate" in label:
                        category_scores[ToxicityCategory.IDENTITY_ATTACK] = score

            # Calculate overall score
            overall = max(category_scores.values()) if category_scores else 0.0

            return ToxicityScore(
                text=text,
                overall_score=overall,
                is_toxic=overall >= self.threshold,
                category_scores=category_scores,
                threshold=self.threshold,
                scorer_type="toxic_bert",
                raw_response={"results": results},
            )

        except Exception as e:
            return ToxicityScore(
                text=text,
                overall_score=0.0,
                is_toxic=False,
                category_scores={},
                threshold=self.threshold,
                scorer_type="toxic_bert",
                raw_response={"error": str(e)},
            )


class SignatureBasedScorer(ToxicityScorerBase):
    """
    Signature-based toxicity scorer (fallback).

    Uses keyword matching for basic toxicity detection.
    Less accurate than ML-based approaches but works offline without dependencies.
    """

    # Toxic content signatures by category
    SIGNATURES = {
        ToxicityCategory.HATE_SPEECH: [
            r'\b(hate|hatred)\b.*\b(group|race|religion|gender)\b',
            r'\b(exterminate|eliminate|kill all)\b.*\b(people|group|race)\b',
            r'\b(subhuman|inferior race|master race)\b',
        ],
        ToxicityCategory.THREAT: [
            r'\b(kill|murder|harm|hurt|attack)\b.*\b(you|them|people)\b',
            r'\b(bomb|weapon|shoot|stab)\b',
            r'\b(threaten|threat)\b',
            r'\bi will\b.*\b(kill|hurt|destroy)\b',
        ],
        ToxicityCategory.IDENTITY_ATTACK: [
            r'\b(all|every)\s+(women|men|blacks|whites|jews|muslims|christians)\b.*\b(are|should)\b',
            r'\b(racial slur pattern)',
        ],
        ToxicityCategory.INSULT: [
            r'\b(idiot|moron|stupid|dumb|retard)\b',
            r'\b(loser|pathetic|worthless)\b',
        ],
        ToxicityCategory.PROFANITY: [
            r'\b(fuck|shit|damn|ass|bitch)\b',
        ],
        ToxicityCategory.SEXUALLY_EXPLICIT: [
            r'\b(sexual|explicit|porn|nude)\b.*\b(content|material|images)\b',
        ],
    }

    def is_available(self) -> bool:
        """Always available as fallback."""
        return True

    def score(self, text: str) -> ToxicityScore:
        """Score text using signature matching."""
        text_lower = text.lower()
        category_scores = {}
        matches = []

        for category, patterns in self.SIGNATURES.items():
            category_score = 0.0
            for pattern in patterns:
                try:
                    if re.search(pattern, text_lower, re.IGNORECASE):
                        category_score = max(category_score, 0.8)
                        matches.append((category.value, pattern))
                except re.error:
                    continue
            if category_score > 0:
                category_scores[category] = category_score

        # Calculate overall score
        overall = max(category_scores.values()) if category_scores else 0.0

        return ToxicityScore(
            text=text,
            overall_score=overall,
            is_toxic=overall >= self.threshold,
            category_scores=category_scores,
            threshold=self.threshold,
            scorer_type="signature_based",
            raw_response={"matches": matches},
        )


class ToxicityScorer:
    """
    Unified toxicity scorer with automatic fallback.

    Tries scorers in order of preference:
    1. Perspective API (if API key available)
    2. Toxic-BERT (if transformers installed)
    3. Signature-based (always available)
    """

    def __init__(
        self,
        preferred_scorer: str = "auto",
        threshold: float = 0.7,
        perspective_api_key: Optional[str] = None,
    ):
        """
        Initialize toxicity scorer.

        Args:
            preferred_scorer: One of "auto", "perspective", "toxic_bert", "signature"
            threshold: Score threshold for toxic classification (0.0-1.0)
            perspective_api_key: Optional API key for Perspective API
        """
        self.threshold = threshold
        self.preferred_scorer = preferred_scorer

        # Initialize all scorers
        self._scorers = {
            "perspective": PerspectiveAPIScorer(perspective_api_key, threshold),
            "toxic_bert": ToxicBERTScorer(threshold),
            "signature": SignatureBasedScorer(threshold),
        }

    def _get_active_scorer(self) -> ToxicityScorerBase:
        """Get the active scorer based on availability."""
        if self.preferred_scorer != "auto":
            scorer = self._scorers.get(self.preferred_scorer)
            if scorer and scorer.is_available():
                return scorer
            # Fall back to signature if preferred not available
            return self._scorers["signature"]

        # Auto mode: try in order of preference
        for scorer_name in ["perspective", "toxic_bert", "signature"]:
            scorer = self._scorers[scorer_name]
            if scorer.is_available():
                return scorer

        return self._scorers["signature"]

    def score(self, text: str) -> ToxicityScore:
        """
        Score text for toxicity.

        Args:
            text: Text to analyze

        Returns:
            ToxicityScore with detailed results
        """
        scorer = self._get_active_scorer()
        return scorer.score(text)

    def is_toxic(self, text: str) -> bool:
        """
        Quick check if text is toxic.

        Args:
            text: Text to analyze

        Returns:
            True if text exceeds toxicity threshold
        """
        return self.score(text).is_toxic

    def get_scorer_type(self) -> str:
        """Get the type of active scorer."""
        return self._get_active_scorer().__class__.__name__


# Convenience function for simple usage
def score_toxicity(
    text: str,
    threshold: float = 0.7,
    scorer: str = "auto",
) -> ToxicityScore:
    """
    Score text for toxicity.

    Args:
        text: Text to analyze
        threshold: Score threshold (0.0-1.0)
        scorer: Scorer type ("auto", "perspective", "toxic_bert", "signature")

    Returns:
        ToxicityScore with detailed results
    """
    return ToxicityScorer(scorer, threshold).score(text)
