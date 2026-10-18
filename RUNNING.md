# Гайд по запуску тестов

Весь смысл — в **двух раздельных прогонах** на двух ядрах, собранных идентично,
кроме zero-copy:

- **Старое ядро** — до фикса (zero-copy в AF_ALG ещё есть).
- **Новое ядро** — с фиксом Eric Biggers (splice копирует внутри).

Один и тот же скрипт запускается на обоих; разделение идёт по колонке `kernel`
(`uname -r`) в CSV. На каждом ядре делаем всё одинаково.

## На каждом ядре

```sh
# 1. собрать
make all

# 2. проверить, что алгоритмы загружены
grep -E 'cbc\(aes\)|gcm\(aes\)|sha256' /proc/crypto

# 3. прогнать матрицу (нужен root для governor/pin и perf)
sudo GOVERNOR=1 PIN_CPU=2 scripts/run_matrix.sh
```

Результат: `results/results_$(uname -r).csv` — по строке на прогон, с метками
`variant` (`afalg-zc` / `afalg-copy` / `userspace-aesni`) и `kernel`.

Быстрый дым-тест без root и perf:
```sh
SIZES="4096 65536 1048576" REPEATS=3 NO_PERF=1 scripts/run_matrix.sh
```

## Свести вместе

Скопировать оба CSV в одну папку и построить графики:
```sh
python3 scripts/plot_results.py results/results_*.csv -o figures --summary results/summary.csv
```
`summary.csv` — среднее и 95% ДИ по каждой ячейке; PNG — серия на `(variant, kernel)`.

## Что сравнивать

| Сравнение | Берём строки | Отвечает на |
|---|---|---|
| **Цена фикса** | `afalg-zc` на старом ядре ↔ `afalg-zc` на новом (одинаковые alg/size/align/threads) | RQ1: сколько стоило удаление zero-copy |
| **Старое vs новое, копия** | `afalg-copy` ↔ `afalg-copy` между ядрами (sanity) | что копия-путь не изменился сам по себе |
| **Разрыв с userspace** | `afalg-*` ↔ `userspace-aesni` на одном ядре | RQ3: держится ли «always slower» |
| **Где падает цена** | та же пара по оси `bytes` + `cycles_per_byte` | RQ2/H2: порог страницы, упор в CPU или память |
| **Параллелизм** | те же пары по оси `threads` | RQ4 |

Ключевые проверки гипотез:
- **H1** — на мелких/невыровненных (`alignment=unaligned`, малый `bytes`) цена
  фикса ≈ 0: `afalg-zc` старое ≈ новое.
- **H2** — разница растёт с `bytes` выше порога страницы (~4 КБ) и до потолка
  zero-copy (~64 КБ); смотреть вместе с `cycles_per_byte`.
- **H3/H4** — `userspace-aesni` быстрее обоих AF_ALG почти везде, и этот разрыв
  заметно больше самой цены фикса.

Сравнивать можно только совпадающие ячейки (одинаковые alg / size / alignment /
threads / op); перекрытие дают пересекающиеся колонки в двух CSV.
