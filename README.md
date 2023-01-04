# lib-injector

动态注入shared lib到现有进程，现阶段计划支持以下平台（已经支持的打勾）

    1、☑️macOS arm64(aarch64)
    2、[TODO] linux amd64

如果是c的话，已经有实现了，我就是参考的那个实现，非常感谢vocaeq！

[vocaeq/inject.c](https://gist.github.com/vocaeq/fbac63d5d36bc6e1d6d99df9c92f75dc)

但是c内存不安全，而且跨平台比较麻烦

于是就想到了rust，并且根据自己的理解对逻辑做了一些小修改

预告：这个项目是某个项目的基础

## License

Apache，反正只要注明出处就行