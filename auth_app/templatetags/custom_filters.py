from django import template
from decimal import Decimal

register = template.Library()

@register.filter
def sub(value, arg):
    """Subtract the arg from the value."""
    try:
        return Decimal(value) - Decimal(arg)
    except (ValueError, TypeError):
        return value