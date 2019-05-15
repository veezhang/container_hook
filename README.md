# container_hook

## build

```shell
docker build --build-arg TAG=18.04 -t veezhang/container_hook:ubuntu18.04 .
```

## test

```shell
docker run -it --rm --cpuset-cpus 0,1 --cpu-quota 200000 -e CONTAINER_HOOK_PROGRAMS=container_hook_test -e LD_PRELOAD=/usr/lib/container_hook.so veezhang/container_hook:ubuntu18.04  /usr/bin/container_hook_test
docker run -it --rm --cpuset-cpus 0,1 --cpu-quota 300000 -e CONTAINER_HOOK_PROGRAMS=container_hook_test -e LD_PRELOAD=/usr/lib/container_hook.so veezhang/container_hook:ubuntu18.04  /usr/bin/container_hook_test
docker run -it --rm --cpuset-cpus 0,1,2,3,4 --cpu-quota 300000 -e CONTAINER_HOOK_PROGRAMS=container_hook_test -e LD_PRELOAD=/usr/lib/container_hook.so veezhang/container_hook:ubuntu18.04  /usr/bin/container_hook_test
```

## usage

```shell
Dockerfile 加入以下部分：
ENV LD_PRELOAD /usr/lib/container_hook.so:${LD_PRELOAD}
ENV CONTAINER_HOOK_PROGRAMS sh:bash:python
COPY --from=container_hook:ubuntu18.04 /usr/lib/container_hook.so /usr/lib/container_hook.so

# 其中CONTAINER_HOOK_PROGRAMS为，需要hook的程序名前缀， 对于的程序可以获取限制后的cpu数目
```
