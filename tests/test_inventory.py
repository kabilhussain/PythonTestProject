"""Partial tests: some pass, some fail (exposing bugs), coverage is incomplete on purpose."""
import pytest

from buggy_app.inventory import Inventory, Item
from buggy_app import logic_bugs


def test_add_and_total():
    inv = Inventory()
    inv.add(Item("apple", 1.0, 10))
    assert inv.total_value() == 10.0


def test_add_twice_accumulates():
    # Fails: exposes BUG I1
    inv = Inventory()
    inv.add(Item("apple", 1.0, 10))
    inv.add(Item("apple", 1.0, 5))
    assert inv.find("apple").quantity == 15


def test_names_sorted():
    # Fails: exposes BUG I8
    inv = Inventory()
    inv.add(Item("b", 1.0))
    inv.add(Item("a", 1.0))
    assert inv.names_sorted() == ["a", "b"]


def test_cheapest_empty():
    # Fails: exposes BUG I6
    assert Inventory().cheapest() is None


def test_mutable_default():
    # Fails: exposes BUG L1
    logic_bugs.append_item(1)
    assert logic_bugs.append_item(2) == [2]


def test_average():
    assert logic_bugs.average([1, 2, 3]) == 2


def test_average_empty():
    with pytest.raises(ZeroDivisionError):
        logic_bugs.average([])


def test_remove_negatives():
    # Fails: exposes BUG L10
    assert logic_bugs.remove_negatives([-1, -2, 3]) == [3]
