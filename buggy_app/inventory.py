"""A small 'real-looking' module with subtle bugs that tests partially catch."""
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Item:
    name: str
    price: float
    quantity: int = 0
    tags: List[str] = field(default_factory=list)


class Inventory:
    def __init__(self):
        self.items: Dict[str, Item] = {}

    def add(self, item: Item) -> None:
        # BUG I1: overwrites existing quantity instead of adding
        self.items[item.name] = item

    def remove(self, name: str, qty: int) -> None:
        item = self.items[name]  # BUG I2: KeyError, no validation
        item.quantity -= qty  # BUG I3: quantity can go negative

    def total_value(self) -> int:  # BUG I4: wrong return type annotation
        total = 0
        for item in self.items.values():
            total += item.price * item.quantity
        return total

    def find(self, name: str) -> Item:  # BUG I5: should be Optional[Item]
        return self.items.get(name)

    def cheapest(self) -> Optional[Item]:
        # BUG I6: crashes on empty inventory
        return min(self.items.values(), key=lambda i: i.price)

    def apply_discount(self, percent: float) -> None:
        for item in self.items.values():
            # BUG I7: percent treated as fraction (10 -> 1000% off)
            item.price = item.price - item.price * percent

    def names_sorted(self) -> List[str]:
        # BUG I8: list.sort() returns None
        return list(self.items.keys()).sort()

    def count(self) -> str:
        return len(self.items)  # BUG I9: returns int but annotated str
