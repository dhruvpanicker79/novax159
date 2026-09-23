"""S9 - posture scoring, grading and aggregation. Deliverable D19.

Owner: person D.

Score 0-100 from weighted category subscores, mapped to an SSL-Labs-style
grade. The capping rules matter more than the weights: any session with
credentials in cleartext caps the host at F regardless of everything else,
because an average that hides a catastrophe is worse than no score at all.
"""
