"""
Revisão espaçada — SM-2 simplificado, com três respostas.

  0 = Esqueci      → volta amanhã, a nota fica "mais difícil"
  1 = Com esforço  → intervalo cresce devagar
  2 = Lembrei      → intervalo cresce pelo fator de facilidade

Notas novas entram na fila no dia seguinte ao que foram escritas.
"""
from datetime import date, timedelta

GRADES = [(0, "Esqueci"), (1, "Com esforço"), (2, "Lembrei")]
DEFAULT_EASE = 2.5
MIN_EASE = 1.3
MAX_INTERVAL = 365


def schedule(grade: int, interval: int, ease: float, reps: int):
    """Retorna (intervalo em dias, facilidade, repetições) depois de uma resposta."""
    if grade == 0:
        return 1, max(MIN_EASE, ease - 0.2), 0

    if grade == 1:
        new = 2 if reps == 0 else max(interval + 1, round(interval * 1.2))
        return min(new, MAX_INTERVAL), max(MIN_EASE, ease - 0.15), reps + 1

    if reps == 0:
        new = 3
    elif reps == 1:
        new = 7
    else:
        new = round(interval * ease)
    return min(max(new, interval + 1), MAX_INTERVAL), ease + 0.05, reps + 1


def previews(interval: int, ease: float, reps: int):
    """Intervalo resultante de cada resposta, para mostrar nos botões."""
    return {g: schedule(g, interval, ease, reps)[0] for g, _ in GRADES}


def human_interval(days: int) -> str:
    if days <= 1:
        return "amanhã"
    if days < 30:
        return f"{days} dias"
    if days < 365:
        months = round(days / 30)
        return "1 mês" if months == 1 else f"{months} meses"
    return "1 ano"


def human_due(due: str, today: date) -> str:
    """'hoje', 'amanhã', 'em 5 dias'… a partir de uma data YYYY-MM-DD."""
    if not due:
        return "hoje"
    delta = (date.fromisoformat(due) - today).days
    if delta <= 0:
        return "hoje"
    if delta == 1:
        return "amanhã"
    return f"em {human_interval(delta)}"


def streak(days_desc, today: date) -> int:
    """Dias seguidos com revisão, contando a partir de hoje (ou de ontem)."""
    seen = {date.fromisoformat(d) for d in days_desc}
    cursor = today if today in seen else today - timedelta(days=1)
    count = 0
    while cursor in seen:
        count += 1
        cursor -= timedelta(days=1)
    return count
