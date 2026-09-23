"""S8 - the three AI layers. Deliverables D16, D17, D18. USP-04.

Owner: person C.

    classifier.py  supervised risk scoring + SHAP explanations      (D16)
    anomaly.py     Isolation Forest + JA3 rarity, unsupervised      (D17)
    priority.py    the triage queue: severity x exposure            (D18)
    train.py       synthetic feature generation + model fitting

Per ADR-0003 the rule engine labels synthetic feature vectors and the model
trains on those. Per ADR-0006 no PCAPs are involved in training at all, which
is what decouples the ML timeline from the parser timeline.
"""
