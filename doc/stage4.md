# SO-shell-etap4
*Specyfikacja czwartego etapu projektu realizowanego w ramach ćwiczeń do przedmiotu Systemy Operacyjne.*

## Implementacja shella - etap 4 (przekierowanie we/wy i łączenie komend pipe'ami).


1. Każdy program uruchamiany z shella może mieć przekierowane wejście i wyjście. Przekierowania dla wbudowanych poleceń shella można ignorować. Lista `redirs` w strukturze `command` zawiera przekierowania zdefiniowane dla danej komendy.

  - Przekierowanie wejścia: jeżeli pole `flags` w w strukturze `redir` spełnia makro `IS_RIN(x)` to nowo uruchomiony program powinien mieć otwarty plik o nazwie wskazanej przez pole `filename` na standardowym wejściu (deskryptor `0`).

  - Przekierowanie wyjścia: jeżeli pole `flags` w w strukturze `redir` spełnia makro `IS_ROUT(x)` lub `IS_RAPPEND(x)` to nowo uruchomiony program powinien mieć otwarty plik o nazwie wskazanej przez pole `filename` na standardowym wyjściu (deskryptor `1`). Dodatkowo jeśli flagi spełniają makro `IS_RAPPEND(x)` to plik powinien zostać otwarty w trybie dopisywania (`O_APPEND`), w przeciwnym przypadku zawartość pliku powinna zostać wyczyszczona (`O_TRUNC`). W przypadku gdy plik do którego przekierowane jest wyjście nie istnieje, powinien zostać stworzony.

  Należy obsłużyć następujące błędy:
  - plik nie istnieje -> wypisz na stderr: `(nazwa pliku): no such file or directory\n`,
  - brak odpowiednich praw dostępu ->  wypisz na stderr: `(nazwa pliku):  permission denied\n`.

  Można przyjąć że lista przekierowań dla każdej komendy zawiera co najwyżej jedno przekierowanie wejścia i co najwyżej jedno przekierowanie wyjścia.

1. Polecenia w jednej linii mogą być połączone pipe'ami `|`. Ciąg takich komend będziemy nazywać pipeline. W przypadku gdy pipeline zawiera więcej niż jedno polecenie można założyć że żadne z nich nie jest komendą wbudowaną shella. Należy wykonać wszystkie polecenia pipeline'a, każde w osobnym procesie potomnym shella. Kolejne polecenia powinny być połączone pipe'ami tak aby wyjście procesu realizującego polecenie k trafiało na wejście procesu polecenia k+1. Shell powinien zawiesić swoje działanie do momentu aż **wszystkie** procesy realizujące polecenia pipeline'a się zakończą. Jeśli polecenie ma zdefiniowane przekierowanie(a) we/wy to mają one pierwszeństwo przed pipe'ami.

1. W jednej linii możne być zdefiniowanych wiele pipeline'ów oddzielonych znakiem `;` (lub `&`). Należy je wykonać sekwencyjnie tzn. wykonać pierwszy poczekać aż wszystkie procesy się zakończą i dopiero wtedy wykonać drugi itd.

Uwaga! Parser akceptuje linie w których znajdują się puste komendy. W szczególności linia zawierająca `ls | sort ; ls |  | wc` zostanie poprawnie sparsowana. Jeśli w linii występuje pipeline o długości przynajmniej 2 zawierający pustą komendę to należy taką linię w całości zignorować i ogłosić syntax error.

Przykład sesji (porównaj wyniki z tym co robi np. bash):
```
$ ls > a
$ ls >> a
$ ls >> b
$ cat < a
$ cat < a > b
$ cat < a >> b
$ ls | sort
...
$ ls | cat | sort | wc
...
$ ls > /dev/null | wc
      0       0       0
$ ls | wc < /dev/null
      0       0       0
$ ls | sleep 10 | ls | sort # shel powinien się zawiesić na 10s.
...
$ ls /etc | grep "a" > a ; ls /home | sort > b
...
$ sleep 5 ; sleep 5; sleep 5; shecho yawn # wykonanie powinna trwac 15s.
yawn
```

Syscall checklist: `open`, `close`, `pipe`, `dup/dup2/fcntl`.

Testy zostały rozbudowane o zestaw 3 obejmujący przekierowania i łączenie komend pipe'ami.
