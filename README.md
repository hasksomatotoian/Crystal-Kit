# Crystal Kit

This repo is a technical and social experiment to explore whether replacing Cobalt Strike's evasion primitives (Sleepmask/BeaconGate) with a [Crystal Palace](https://tradecraftgarden.org/) PICO is feasible (or even desirable) for advanced evasion scenarios.

## Usage (hasksomatotoian fork)

1. Clone the latest Crystal Kit repo:

```dos
cd C:\Users\janta\repos
git clone https://github.com/hasksomatotoian/Crystal-Kit.git
```

2. Build Crystal Kit

```shell
cd /mnt/c/Users/janta/repos/Crystal-Kit
make clean && make all
```

3. Download the latest Cobalt Strike Linux package and extract it to the `/opt/cobaltstrike` folder.

4. Start CS Teams Server.

```shell
cd /opt/cobaltstrike/server
./teamserver 172.23.112.24 heslo /mnt/c/Users/janta/repos/Crystal-Kit/loader/malleableC2profile/default.profile
```

5. Download latest Cobalt Strike Windows package and extract it to the `C:\Tools\cobaltstrike` folder.

6. Extract `crystalpalace.jar` from the latest [Crystal Palace Release ZIP](https://tradecraftgarden.org/crystalpalace.html) and copy it inside the Cobalt Strike client directory `C:\Tools\cobaltstrike\client`, alongside `cobaltstrike-client.jar`

7. Open CS and load the `C:\Users\janta\repos\Crystal-Kit\crystalkit.cna` file using menu **Cobalt Strike > Script Manager**.

8. Generate a new payload. Monitor script output in the **Script Console** to ensure, that there were no errors during the script execution.

## Usage (original)

1. Disable the sleepmask and stage obfuscations in Malleable C2.

```text
stage {
    set sleep_mask "false";
    set cleanup "true";
    transform-obfuscate { }
}

post-ex {
    set cleanup "true";
    set smartinject "true";
}
```

2. Copy `crystalpalace.jar` to your Cobalt Strike client directory.
3. Load `crystalkit.cna`.  

### Notes

- Tested on Cobalt Strike 4.12.
- Can work with any post-ex DLL capability.
