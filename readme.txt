pyinstaller --onefile  --noconsole --upx-dir ".\upx-4.1.0-win64" randompick-utf8.py

nuitka --standalone --windows-console-mode=disable --enable-plugin=tk-inter  --onefile --remove-output  randompick-utf8.py


pyinstaller --onefile --noconsole  --upx-dir ".\upx-4.1.0-win64" poc_judge_selector.py

nuitka --standalone --windows-console-mode=disable --enable-plugin=tk-inter  --onefile --remove-output  poc_judge_selector.py
