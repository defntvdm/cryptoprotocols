Протокол условного срабатывания

Протокол позволяет изменить логику программы в зависимости от некоторого
условия. В текущей реализации логика меняется заполнении памяти > 70%

Запускается сервер, слушающий порт 31337 / UDP.
Запоминает всё, что приходит в сокет.
При загрузке памяти начинает отвечать, что больше ничего не принимаем.

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!                           !!!
!!! Работает только на Linux. !!!
!!!                           !!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

для проверки можно запустить `./main.py`
и затем в другом терминале запустить `yes | nc -u 127.0.0.1 31337` и подождать,
пока память не забьётся
