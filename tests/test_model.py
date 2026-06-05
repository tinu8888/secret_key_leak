"""Tests for dlsca.model, save/load round-trip + card-driven preprocessing.

Kept deliberately tiny (small net, few traces, 1 epoch) so the suite stays fast. The two
obligations for the model card are checked:

  1. ``save`` -> ``load`` restores identical predictions on a fixed input;
  2. the loaded card re-applies ``poi_window`` + ``normalization`` so a model fed a *raw*
     trace produces the same output as during training.
"""

import numpy as np
import pytest

torch = pytest.importorskip("torch")

from dlsca import model


def _tiny_set(seed=0, n=40, s=60):
    rng = np.random.default_rng(seed)
    traces = rng.normal(size=(n, s)).astype(np.float32)
    labels = rng.integers(0, 256, size=n)
    return traces, labels


def test_save_load_restores_identical_predictions(tmp_path):
    traces, labels = _tiny_set(seed=1)
    poi = (10, 40)  # 30-sample window
    net = model.build(poi[1] - poi[0])
    card = model.train(
        net, traces, labels, poi, seed=1,
        name="t_round", target_byte=3, train_set="tiny",
        epochs=1, batch_size=16, val_frac=0.1, prefer_mps=False,
    )
    model.save(net, card, models_dir=str(tmp_path))

    # Reference predictions on RAW traces (card applies poi+normalization internally).
    before = model.predict_log_proba(net, traces, card, prefer_mps=False)

    loaded_net, loaded_card = model.load("t_round", models_dir=str(tmp_path))
    after = model.predict_log_proba(loaded_net, traces, loaded_card, prefer_mps=False)

    assert np.allclose(before, after, atol=1e-5)
    # Same predicted class for every trace.
    assert np.array_equal(before.argmax(1), after.argmax(1))


def test_loaded_card_reapplies_poi_and_normalization(tmp_path):
    traces, labels = _tiny_set(seed=2)
    poi = (5, 35)
    net = model.build(poi[1] - poi[0])
    card = model.train(
        net, traces, labels, poi, seed=2,
        name="t_card", target_byte="per-byte", train_set="tiny",
        epochs=1, batch_size=16, prefer_mps=False,
    )
    model.save(net, card, models_dir=str(tmp_path))
    _, loaded_card = model.load("t_card", models_dir=str(tmp_path))

    # Card carries the exact transform needed to reproduce training input.
    assert loaded_card["poi_window"] == [poi[0], poi[1]]
    assert len(loaded_card["normalization"]["mean"]) == poi[1] - poi[0]
    assert len(loaded_card["normalization"]["std"]) == poi[1] - poi[0]
    assert loaded_card["label_model"] == "identity-256"
    assert loaded_card["device"] in ("mps", "cpu")


def test_build_output_shape():
    net = model.build(40, n_classes=256)
    x = torch.zeros(7, 40)
    out = net(x)
    assert out.shape == (7, 256)
