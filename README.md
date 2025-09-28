打包方法一：
pyinstaller --onefile --noconsole  --upx-dir ".\upx-4.1.0-win64" poc_judge_selector.py

打包方法二：
nuitka --standalone --windows-console-mode=disable --enable-plugin=tk-inter  --onefile --remove-output  poc_judge_selector.py
