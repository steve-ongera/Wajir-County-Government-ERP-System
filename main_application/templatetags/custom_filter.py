from django import template

register = template.Library()

@register.filter(name='mul')
def mul(value, arg):
    """Multiply two numbers."""
    try:
        return float(value) * float(arg)
    except (ValueError, TypeError):
        return ''

@register.filter(name='div')
def div(value, arg):
    """Divide value by arg."""
    try:
        arg = float(arg)
        if arg == 0:
            return '∞'  # avoid ZeroDivisionError
        return float(value) / arg
    except (ValueError, TypeError):
        return ''


@register.filter
def abs(value):
    """Return absolute value"""
    try:
        return abs(int(value))
    except (ValueError, TypeError):
        return value