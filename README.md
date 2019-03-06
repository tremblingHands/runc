# runc

docker 运行在 android 系统上

系统：android-7.1.1

内核：3.10-nougat

设备：nexus-9

## v1 namespace_ipc

`./runc_logTofile --root /storage/run run container1`

```
container_linux.go:337: starting container process caused "process_linux.go:335: 
running exec setns process for init caused \"exit status 46\""

```


libcontainer/process_linux.go : 342

```go
if err := p.execSetns(); err != nil {
	return newSystemErrorWithCause(err, "running exec setns process for init")
}
```

libcontainer/process_linux.go : 244

```go
func (p *initProcess) execSetns() error {
        status, err := p.cmd.Process.Wait()
        if err != nil {
                p.cmd.Wait()
                fmt.Printf("1\n")
                return err
        }
        if !status.Success() {
                p.cmd.Wait()
                fmt.Printf("2\n")
                return &exec.ExitError{ProcessState: status}
        }
	···
	···
```

libcontainer/process_linux.go : 284

```go
func (p *initProcess) start() error {
        defer p.parentPipe.Close()
		fmt.Printf("omni : %+v\n", p.cmd)
        err := p.cmd.Start()
        ···
        ···
```


```bash
omni : &{Path:/proc/self/exe Args:[./runc_logTofile init] Env:[GOMAXPROCS= 
_LIBCONTAINER_CONSOLE=3 _LIBCONTAINER_INITPIPE=4 _LIBCONTAINER_FIFOFD=5 
_LIBCONTAINER_INITTYPE=standard] Dir:/data/test/runc/rootfs Stdin:<nil> Stdout:
<nil> Stderr:<nil> ExtraFiles:[0x4420074090 0x44200740a0 0x44200740b0] 
SysProcAttr:0x44200ac090 Process:<nil> ProcessState:<nil> ctx:<nil> lookPathErr:<nil> 
finished:false childFiles:[] closeAfterStart:[] closeAfterWait:[] goroutine:[] 
errch:<nil> waitDone:<nil>}

```


```go
func (p *initProcess) start() (err error) {
        defer p.parentPipe.Close()
        //omni
        stdLogFile, err:=os.Create("/storage/omni_log")
        if err!=nil {
                fmt.Printf("omni create log file failed")
                return err
        }
        p.cmd.Stdout=stdLogFile
        p.cmd.Stderr=stdLogFile
        //omni
        
        err = p.cmd.Start()
        
        //omni
        fmt.Printf("omni after start: %+v\n", p.cmd)
        //omni
        p.childPipe.Close()
        
```

```bash
omni : &{Path:/proc/self/exe Args:[./runc_logTofile init] Env:[GOMAXPROCS= 
_LIBCONTAINER_CONSOLE=3 _LIBCONTAINER_INITPIPE=4 _LIBCONTAINER_FIFOFD=5 
_LIBCONTAINER_INITTYPE=standard] Dir:/data/test/runc/rootfs Stdin:<nil> Stdout:
0x4420074008 Stderr:0x4420074010 ExtraFiles:[0x4420074090 0x44200740a0 0x44200740b0] 
SysProcAttr:0x44200ac090 Process:<nil> ProcessState:<nil> ctx:<nil> lookPathErr:<nil> 
finished:false childFiles:[] closeAfterStart:[] closeAfterWait:[] goroutine:[] 
errch:<nil> waitDone:<nil>}

nsenter: failed to unshare namespaces: m

```

libcontainer/nsenter/nsexec.c : 875

```c
if (unshare(config.cloneflags) < 0)
                                bail("failed to unshare namespaces");

```

libcontainer/nsenter/nsexec.c : 132

```c
#define bail(fmt, ...)                                                          \
        do {                                                                    \
                int ret = __COUNTER__ + 1;                                      \
                fprintf(stderr, "nsenter: " fmt ": %m\n", ##__VA_ARGS__);       \
                if (syncfd >= 0) {                                              \
                        enum sync_t s = SYNC_ERR;                               \
                        if (write(syncfd, &s, sizeof(s)) != sizeof(s))          \
                                fprintf(stderr, "nsenter: failed: write(s)");   \
                        if (write(syncfd, &ret, sizeof(ret)) != sizeof(ret))    \
                                fprintf(stderr, "nsenter: failed: write(ret)"); \
                }                                                               \
                exit(ret);                                                      \
        } while(0)
```


: 544

```c
void nsexec(void)
{
		···
		···
        pipenum = initpipe();
        if (pipenum == -1)
                return;

        /* Parse all of the netlink configuration. */
        nl_parse(pipenum, &config);
        ···
        ···
}
```

: 333

```c
static int initpipe(void)
{
        int pipenum;
        char *initpipe, *endptr;

        initpipe = getenv("_LIBCONTAINER_INITPIPE");
        if (initpipe == NULL || *initpipe == '\0')
                return -1;

        pipenum = strtol(initpipe, &endptr, 10);
        if (*endptr != '\0')
                bail("unable to parse _LIBCONTAINER_INITPIPE");

        return pipenum;
}
```

libcontainer/container_linux.go: 475

```go
cmd.ExtraFiles = append(cmd.ExtraFiles, childPipe)
cmd.Env = append(cmd.Env,
	fmt.Sprintf("_LIBCONTAINER_INITPIPE=%d", stdioFdCount+len(cmd.ExtraFiles)-1),)
```

libcontainer/container_linux.go  : 431

```go
func (c *linuxContainer) newParentProcess(p *Process) (parentProcess, error) {
        parentPipe, childPipe, err := utils.NewSockPair("init")
                if err != nil {
                return nil, newSystemErrorWithCause(err, "creating new init pipe")
        }
        cmd, err := c.commandTemplate(p, childPipe)
        if err != nil {
                return nil, newSystemErrorWithCause(err, "creating new command template")
        }
        if !p.Init {
                return c.newSetnsProcess(p, cmd, parentPipe, childPipe)
        }

        // We only set up fifoFd if we're not doing a `runc exec`. The historic
        // reason for this is that previously we would pass a dirfd that allowed
        // for container rootfs escape (and not doing it in `runc exec` avoided
        // that problem), but we no longer do that. However, there's no need to do
        // this for `runc exec` so we just keep it this way to be safe.
        if err := c.includeExecFifo(cmd); err != nil {
                return nil, newSystemErrorWithCause(err, "including execfifo in cmd.Exec setup")
        }
        return c.newInitProcess(p, cmd, parentPipe, childPipe)
}
```

```go
func (c *linuxContainer) newSetnsProcess(p *Process, cmd *exec.Cmd, parentPipe, childPipe *os.File) (*setnsProcess, error) {
        cmd.Env = append(cmd.Env, "_LIBCONTAINER_INITTYPE="+string(initSetns))
        state, err := c.currentState()
        if err != nil {
                return nil, newSystemErrorWithCause(err, "getting container's current state")
        }
        // for setns process, we don't have to set cloneflags as the process namespaces
        // will only be set via setns syscall
        data, err := c.bootstrapData(0, state.NamespacePaths)
        if err != nil {
                return nil, err
        }
        return &setnsProcess{
                cmd:             cmd,
                cgroupPaths:     c.cgroupManager.GetPaths(),
                rootlessCgroups: c.config.RootlessCgroups,
                intelRdtPath:    state.IntelRdtPath,
                childPipe:       childPipe,
                parentPipe:      parentPipe,
                config:          c.newInitConfig(p),
                process:         p,
                bootstrapData:   data,
        }, nil
}
```

libcontainer/process_linux.go : 330

```go
func (p *initProcess) start() error {
		···
		···
        if _, err := io.Copy(p.parentPipe, p.bootstrapData); err != nil {
                return newSystemErrorWithCause(err, "copying bootstrap data to pipe")
        }
        ···
        ···
}
```

libcontainer/container_linux.go

```go
508

data, err := c.bootstrapData(c.config.Namespaces.CloneFlags(), nsMaps)

534

data, err := c.bootstrapData(0, state.NamespacePaths)
```

libcontainer/container_linux.go : 486

```go
func (c *linuxContainer) newInitProcess(p *Process, cmd *exec.Cmd, parentPipe, childPipe *os.File) (*initProcess, error) {
        cmd.Env = append(cmd.Env, "_LIBCONTAINER_INITTYPE="+string(initStandard))
        nsMaps := make(map[configs.NamespaceType]string)
        for _, ns := range c.config.Namespaces {
                if ns.Path != "" {
                        nsMaps[ns.Type] = ns.Path
                }
        }
        _, sharePidns := nsMaps[configs.NEWPID]
        data, err := c.bootstrapData(c.config.Namespaces.CloneFlags(), nsMaps)
        if err != nil {
                return nil, err
        }
        return &initProcess{
                cmd:             cmd,
                childPipe:       childPipe,
                parentPipe:      parentPipe,
                manager:         c.cgroupManager,
                intelRdtManager: c.intelRdtManager,
                config:          c.newInitConfig(p),
                container:       c,
                process:         p,
                bootstrapData:   data,
                sharePidns:      sharePidns,
        }, nil
}

```



libcontainer/specconv : 144

```go
···
···
{
  Type: "ipc",
},
···
···
```




libcontainer/factory_linux.go : 283

```go
func (l *LinuxFactory) StartInitialization() (err error) {
	···
	···
	envFifoFd      = os.Getenv("_LIBCONTAINER_FIFOFD")
	fifofd, err = strconv.Atoi(envFifoFd)
	i, err := newContainerInit(it, pipe, consoleSocket, fifofd)
	···
	···
}
```

## s1

libcontainer/specconv/example.go : 12

```go
/** omni
{
        Type: "ipc",
},
**/ 
```


## v2 mqueue

```
container_linux.go:337: starting container process caused 
"process_linux.go:436: container init caused \"rootfs_linux.go:58: 
mounting \\\"mqueue\\\" to rootfs \\\"/data/test/runc/rootfs\\\" at \
\\"/dev/mqueue\\\" caused \\\"no such device\\\"\""
```

libcontainer/rootfs_linux.go : 185

```go
func mountToRootfs(m *configs.Mount, rootfs, mountLabel string) error {
        var (
                dest = m.Destination
        )
        if !strings.HasPrefix(dest, rootfs) {
                dest = filepath.Join(rootfs, dest)
        }

        switch m.Device {
        case "proc", "sysfs":
                if err := os.MkdirAll(dest, 0755); err != nil {
                        return err
                }
                // Selinux kernels do not support labeling of /proc or /sys
                return mountPropagate(m, rootfs, "")
        case "mqueue":
                // omni
                fmt.Printf("\nomni : mountToRootfs dest=%s\n", dest)
                // omni
                if err := os.MkdirAll(dest, 0755); err != nil {
                        return err
                }
                if err := mountPropagate(m, rootfs, mountLabel); err != nil {
                        // older kernels do not support labeling of /dev/mqueue
                        if err := mountPropagate(m, rootfs, ""); err != nil {
                                return err
                        }
                        return label.SetFileLabel(dest, mountLabel)
                }
                return nil
        case "tmpfs":
                copyUp := m.Extensions&configs.EXT_COPYUP == configs.EXT_COPYUP
                tmpDir := ""
                stat, err := os.Stat(dest)
                if err != nil {
                        if err := os.MkdirAll(dest, 0755); err != nil {
                                return err
                        }
                }
                if copyUp {
                        tmpdir, err := prepareTmp("/tmp")
                        if err != nil {
                                return newSystemErrorWithCause(err, "tmpcopyup: failed to setup tmpdir")
                        }
                        defer cleanupTmp(tmpdir)
                        tmpDir, err = ioutil.TempDir(tmpdir, "runctmpdir")
                        if err != nil {
                                return newSystemErrorWithCause(err, "tmpcopyup: failed to create tmpdir")
                        }
                        defer os.RemoveAll(tmpDir)
                        m.Destination = tmpDir
                }
                if err := mountPropagate(m, rootfs, mountLabel); err != nil {
                        return err
                }
                if copyUp {
                        if err := fileutils.CopyDirectory(dest, tmpDir); err != nil {
                                errMsg := fmt.Errorf("tmpcopyup: failed to copy %s to %s: %v", dest, tmpDir, err)
                                if err1 := unix.Unmount(tmpDir, unix.MNT_DETACH); err1 != nil {
                                        return newSystemErrorWithCausef(err1, "tmpcopyup: %v: failed to unmount", errMsg)
                                }
                                return errMsg
                        }
                        }
                        if err := unix.Mount(tmpDir, dest, "", unix.MS_MOVE, ""); err != nil {
                                errMsg := fmt.Errorf("tmpcopyup: failed to move mount %s to %s: %v", tmpDir, dest, err)
                                if err1 := unix.Unmount(tmpDir, unix.MNT_DETACH); err1 != nil {
                                        return newSystemErrorWithCausef(err1, "tmpcopyup: %v: failed to unmount", errMsg)
                                }
                                return errMsg
                        }
                }
                if stat != nil {
                        if err = os.Chmod(dest, stat.Mode()); err != nil {
                                return err
                        }
                }
                return nil
        case "bind":
                stat, err := os.Stat(m.Source)
                if err != nil {
                        // error out if the source of a bind mount does not exist as we will be
                        // unable to bind anything to it.
                        return err
                }
                // ensure that the destination of the bind mount is resolved of symlinks at mount time because
                // any previous mounts can invalidate the next mount's destination.
                // this can happen when a user specifies mounts within other mounts to cause breakouts or other
                // evil stuff to try to escape the container's rootfs.
                if dest, err = securejoin.SecureJoin(rootfs, m.Destination); err != nil {
                        return err
                }
                if err := checkMountDestination(rootfs, dest); err != nil {
                        return err
                }
                // update the mount with the correct dest after symlinks are resolved.
                m.Destination = dest
                if err := createIfNotExists(dest, stat.IsDir()); err != nil {
                        return err
                }
                if err := mountPropagate(m, rootfs, mountLabel); err != nil {
                        return err
                }
                // bind mount won't change mount options, we need remount to make mount options effective.
                // first check that we have non-default options required before attempting a remount
                if m.Flags&^(unix.MS_REC|unix.MS_REMOUNT|unix.MS_BIND) != 0 {
                        // only remount if unique mount options are set
                        if err := remount(m, rootfs); err != nil {
                                return err
                        }
                }

                if m.Relabel != "" {
                        if err := label.Validate(m.Relabel); err != nil {
                                return err
                        }
                        shared := label.IsShared(m.Relabel)
                        if err := label.Relabel(m.Source, mountLabel, shared); err != nil {
                                return err
                        }
                }
        case "cgroup":
                binds, err := getCgroupMounts(m)
                if err != nil {
                        return err
                }
                var merged []string
                for _, b := range binds {
                        ss := filepath.Base(b.Destination)
                        if strings.Contains(ss, ",") {
                                merged = append(merged, ss)
                        }
                }
                tmpfs := &configs.Mount{
                        Source:           "tmpfs",
                        Device:           "tmpfs",
                        Destination:      m.Destination,
                        Flags:            defaultMountFlags,
                        Data:             "mode=755",
                        PropagationFlags: m.PropagationFlags,
                }
                if err := mountToRootfs(tmpfs, rootfs, mountLabel); err != nil {
                        return err
                }
                for _, b := range binds {
                        if err := mountToRootfs(b, rootfs, mountLabel); err != nil {
                                return err
                        }
                }
                for _, mc := range merged {
                        for _, ss := range strings.Split(mc, ",") {
                                // symlink(2) is very dumb, it will just shove the path into
                                // the link and doesn't do any checks or relative path
                                // conversion. Also, don't error out if the cgroup already exists.
                                if err := os.Symlink(mc, filepath.Join(rootfs, m.Destination, ss)); err != nil && !os.IsExist(err) {
                                        return err
                                }
                        }
                }
                if m.Flags&unix.MS_RDONLY != 0 {
                        // remount cgroup root as readonly
                        mcgrouproot := &configs.Mount{
                                Source:      m.Destination,
                                Device:      "bind",
                                Destination: m.Destination,
                                Flags:       defaultMountFlags | unix.MS_RDONLY | unix.MS_BIND,
                        }
                        if err := remount(mcgrouproot, rootfs); err != nil {
                                return err
                        }
                }
        default:
                // ensure that the destination of the mount is resolved of symlinks at mount time because
                // any previous mounts can invalidate the next mount's destination.
                // this can happen when a user specifies mounts within other mounts to cause breakouts or other
                // evil stuff to try to escape the container's rootfs.
                var err error
                if dest, err = securejoin.SecureJoin(rootfs, m.Destination); err != nil {
                        return err
                }
                if err := checkMountDestination(rootfs, dest); err != nil {
                        return err
                }
                // update the mount with the correct dest after symlinks are resolved.
                m.Destination = dest
                if err := os.MkdirAll(dest, 0755); err != nil {
                        return err
                }
                return mountPropagate(m, rootfs, mountLabel)
        }
        return nil
}

```


libcontainer/rootfs_linux.go  : 842

```go
func mountPropagate(m *configs.Mount, rootfs string, mountLabel string) error {
        var (
                dest  = m.Destination
                data  = label.FormatMountLabel(m.Data, mountLabel)
                flags = m.Flags
        )
        if libcontainerUtils.CleanPath(dest) == "/dev" {
                flags &= ^unix.MS_RDONLY
        }

        copyUp := m.Extensions&configs.EXT_COPYUP == configs.EXT_COPYUP
        if !(copyUp || strings.HasPrefix(dest, rootfs)) {
                dest = filepath.Join(rootfs, dest)
        }
        // omni
        fmt.Printf("\n\nomni : mountPropagate dest=%s, data=%s, flags=%v, m=%v\n\n", dest, data, flags, m)
        // omni
        if err := unix.Mount(m.Source, dest, m.Device, uintptr(flags), data); err != nil {
                return err
        }
        for _, pflag := range m.PropagationFlags {
                if err := unix.Mount("", dest, "", uintptr(pflag), ""); err != nil {
                        return err
                }
        }
        return nil
}

```

```
omni : mountPropagate dest=/data/test/runc/rootfs/dev/mqueue, data=, 
flags=14, m=&{mqueue /dev/mqueue mqueue 14 []   0 [] []}
```

```yaml
        "mounts": [
                {
                        "destination": "/proc",
                        "type": "proc",
                        "source": "proc"
                },
                {
                        "destination": "/dev",
                        "type": "tmpfs",
                        "source": "tmpfs",
                        "options": [
                                "nosuid",
                                "strictatime",
                                "mode=755",
                                "size=65536k"
                        ]
                },
                {
                        "destination": "/dev/pts",
                        "type": "devpts",
                        "source": "devpts",
                        "options": [
                                "nosuid",
                                "noexec",
                                "newinstance",
                                "ptmxmode=0666",
                                "mode=0620",
                                "gid=5"
                        ]
                },
                {
                        "destination": "/dev/shm",
                        "type": "tmpfs",
                        "source": "shm",
                        "options": [
                                "nosuid",
                                "noexec",
                                "nodev",
                                "mode=1777",
                                "size=65536k"
                        ]
                },
                {
                        "destination": "/dev/mqueue",
                        "type": "mqueue",
                        "source": "mqueue",
                        "options": [
                                "nosuid",
                                "noexec",
                                "nodev"
                        ]
                },
                {
                        "destination": "/sys",
                        "type": "sysfs",
                        "source": "sysfs",
                        "options": [
                                "nosuid",
                                "noexec",
                                "nodev",
                                "ro"
                        ]
                },
                {
                        "destination": "/sys/fs/cgroup",
                        "type": "cgroup",
                        "source": "cgroup",
                        "options": [
                                "nosuid",
                                "noexec",
                                "nodev",
                                "relatime",
                                "ro"
                        ]
                }
        ],

```

## v2

open config mqueue

## v3 pivotRoot

```
container_linux.go:337: starting container process caused 
"process_linux.go:436: container init caused \"rootfs_linux.go:109: 
jailing process inside rootfs caused \\\"pivot_root invalid argument\
\\"\""
```

libcontainer/rootfs_linux.go : 675

```go
// pivotRoot will call pivot_root such that rootfs becomes the new root
// filesystem, and everything else is cleaned up.
func pivotRoot(rootfs string) error {
        // While the documentation may claim otherwise, pivot_root(".", ".") is
        // actually valid. What this results in is / being the new root but
        // /proc/self/cwd being the old root. Since we can play around with the cwd
        // with pivot_root this allows us to pivot without creating directories in
        // the rootfs. Shout-outs to the LXC developers for giving us this idea.

        fmt.Printf("omni : pivotRoot rootfs=%s\n", rootfs)

        oldroot, err := unix.Open("/", unix.O_DIRECTORY|unix.O_RDONLY, 0)
        if err != nil {
                return err
        }
        defer unix.Close(oldroot)

        newroot, err := unix.Open(rootfs, unix.O_DIRECTORY|unix.O_RDONLY, 0)
        if err != nil {
                return err
        }
        defer unix.Close(newroot)

        // Change to the new root so that the pivot_root actually acts on it.
        if err := unix.Fchdir(newroot); err != nil {
                return err
        }

        if err := unix.PivotRoot(".", "."); err != nil {
                return fmt.Errorf("pivot_root %s", err)
        }
        // Currently our "." is oldroot (according to the current kernel code).
        // However, purely for safety, we will fchdir(oldroot) since there isn't
        // really any guarantee from the kernel what /proc/self/cwd will be after a
        // pivot_root(2).

        if err := unix.Fchdir(oldroot); err != nil {
                return err
        }

        // Make oldroot rslave to make sure our unmounts don't propagate to the
        // host (and thus bork the machine). We don't use rprivate because this is
        // known to cause issues due to races where we still have a reference to a
        // mount while a process in the host namespace are trying to operate on
        // something they think has no mounts (devicemapper in particular).
        if err := unix.Mount("", ".", "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
                return err
        }
        // Preform the unmount. MNT_DETACH allows us to unmount /proc/self/cwd.
        if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
                return err
        }

        // Switch back to our shiny new root.
        if err := unix.Chdir("/"); err != nil {
                return fmt.Errorf("chdir / %s", err)
        }
        return nil
}

```

## s3

android-kernel/kernel/tegra/fs : 2651

```c

 * Also, the current root cannot be on the 'rootfs' (initial ramfs) filesystem.
 * See Documentation/filesystems/ramfs-rootfs-initramfs.txt for alternatives
 * in this situation.

```

due to android rootfs initramfs, change to chroot


## v4 devpts

```
container_linux.go:337: starting container process caused "process_linux.go:436: container init caused \"open /dev/ptmx: no such file or directory\""
```

## s4

```
DEVPTS_MULTIPLE_INSTANCES=Y
Prompt: Support multiple instances of devpts  
```

## v5 

```
standard_init_linux.go:203: exec user process caused "exec format error"
```

## s5

use busybox-arm rootfs as new root

```bash
wget https://busybox.net/downloads/binaries/1.21.1/busybox-armv7l
adb shell rm -rf /data/test/runc/rootfs/bin/*
adb push busybox-armv7l /data/test/runc/rootfs/bin busybox
adb shell
cd /data/test/runc/rootfs/bin/
busybox --install . 

```


## issue

libcontainer/configs/validate/validator.go : 135

```go
return fmt.Errorf("sysctl %q is not allowed in the hosts ipc namespace", s)
```

```
mount tmpfs /run
```

```
config.json from example, edit ipc_namespace and root read only
```
