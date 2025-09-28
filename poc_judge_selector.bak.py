import tkinter as tk
from tkinter import messagebox, simpledialog, ttk, filedialog
import configparser
import random
import csv
import os
import uuid
from datetime import datetime
import json
import re

class POCJudgeSelector:
    def __init__(self, root):
        self.root = root
        self.root.title("POC评委名单抽签器")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)
        
        # 设置中文字体
        self.style = ttk.Style()
        self.style.configure("TLabel", font=("SimHei", 10))
        self.style.configure("TButton", font=("SimHei", 10))
        self.style.configure("TCombobox", font=("SimHei", 10))
        self.style.configure("Header.TLabel", font=("SimHei", 16, "bold"))
        self.style.configure("SubHeader.TLabel", font=("SimHei", 12, "bold"))
        
        # 数据初始化
        self.config_file = "roles_config.ini"
        self.audit_log_file = "audit_log.txt"
        self.current_operation_id = None
        self.drawing_in_progress = False
        self.drawing_results = {}  # 存储抽签结果
        self.second_judges = {}    # 存储第二顺位评委
        
        # 加载配置
        self.config = configparser.ConfigParser()
        self.load_config()
        
        # 创建UI
        self.create_widgets()
        
    def load_config(self):
        """加载配置文件，如果不存在则创建默认配置"""
        if not os.path.exists(self.config_file):
            self.create_default_config()
        
        try:
            self.config.read(self.config_file, encoding="utf-8")
            self.projects = self.config.get("projects", "project_list").split(",")
            self.role_groups = {}
            
            # 加载所有评委组配置
            for section in self.config.sections():
                if section.endswith("_roles"):
                    roles = {}
                    for key, value in self.config.items(section):
                        roles[key] = value.split(",")
                    self.role_groups[section] = roles
                    
        except Exception as e:
            print(f"加载配置文件时出错: {str(e)}")
            messagebox.showerror("错误", f"加载配置文件时出错: {str(e)}")
    
    def refresh_ui(self):
        """刷新UI元素，特别是下拉框"""
        try:
            # 保存当前选择的值
            current_project = self.project_var.get()
            current_role_group_display = self.role_group_var.get()
            
            # 重新加载配置
            self.load_config()
            
            # 更新项目下拉框
            # 找到项目下拉框组件
            for child in self.root.winfo_children():
                if isinstance(child, ttk.Frame):
                    for grandchild in child.winfo_children():
                        if isinstance(grandchild, ttk.LabelFrame) and "抽签配置" in grandchild["text"]:
                            for great_grandchild in grandchild.winfo_children():
                                if isinstance(great_grandchild, ttk.Combobox):
                                    # 检查是否是项目下拉框（根据宽度判断）
                                    if great_grandchild["width"] == 30:
                                        # 更新项目下拉框值
                                        great_grandchild['values'] = self.projects
                                        # 如果之前选择的项目仍然存在，则保持选中
                                        if current_project in self.projects:
                                            self.project_var.set(current_project)
                                        elif self.projects:
                                            self.project_var.set(self.projects[0])
                                        break
            
            # 更新评委组下拉框
            # 创建键名到中文名称的映射
            self.role_group_display_names = {}
            display_values = []
            for key in self.role_groups.keys():
                if key == "3_roles":
                    display_name = "3个评委"
                elif key == "5_roles":
                    display_name = "5个评委"
                else:
                    # 对于其他可能的配置，去掉"_roles"后缀并添加中文说明
                    base_name = key.replace("_roles", "")
                    display_name = f"{base_name}个评委"
                self.role_group_display_names[display_name] = key
                display_values.append(display_name)
            
            # 找到并更新评委组下拉框
            for child in self.root.winfo_children():
                if isinstance(child, ttk.Frame):
                    for grandchild in child.winfo_children():
                        if isinstance(grandchild, ttk.LabelFrame) and "抽签配置" in grandchild["text"]:
                            for great_grandchild in grandchild.winfo_children():
                                if isinstance(great_grandchild, ttk.Combobox):
                                    # 检查是否是评委组下拉框（根据宽度判断）
                                    if great_grandchild["width"] == 15:
                                        # 更新评委组下拉框值
                                        great_grandchild['values'] = display_values
                                        # 如果之前选择的评委组仍然存在，则保持选中
                                        if current_role_group_display in display_values:
                                            self.role_group_var.set(current_role_group_display)
                                        elif display_values:
                                            self.role_group_var.set(display_values[0])
                                        # 更新角色列表
                                        self.update_roles()
                                        break
        except Exception as e:
            print(f"刷新UI时出错: {str(e)}")
            messagebox.showerror("配置错误", f"加载配置文件失败: {str(e)}\n将使用默认配置")
            self.create_default_config()
            self.load_config()
    
    def create_default_config(self):
        """创建默认配置文件"""
        try:
            config = configparser.ConfigParser()
            
            # 项目列表
            config["projects"] = {
                "project_list": "智能客服系统POC,人脸识别系统POC,大数据分析平台POC,云计算资源管理POC,区块链应用POC,物联网网关POC,移动支付安全POC,网络安全防护POC"
            }
            
            # 3组评委
            config["3_roles"] = {
                "主评委": "张评委,李评委,王评委,赵评委,陈评委,杨评委,黄评委,周评委,吴评委,郑评委,孙评委,徐评委,马评委,朱评委,胡评委,林评委,郭评委,何评委,高评委,罗评委",
                "技术评委": "刘工,孙工,周工,吴工,郑工,王工,赵工,钱工,孙工,李工,周工,吴工,郑工,王工,冯工,陈工,褚工,卫工,蒋工,沈工",
                "业务评委": "市场张,市场李,市场王,市场赵,市场陈,市场杨,市场黄,市场周,市场吴,市场郑,销售孙,销售徐,销售马,销售朱,销售胡,销售林,销售郭,销售何,销售高,销售罗"
            }
            
            # 5组评委
            config["5_roles"] = {
                "资深评委": "资深张,资深李,资深王,资深赵,资深陈,资深杨,资深黄,资深周,资深吴,资深郑,资深孙,资深徐,资深马,资深朱,资深胡,资深林,资深郭,资深何,资深高,资深罗",
                "架构评委": "架构张,架构李,架构王,架构赵,架构陈,架构杨,架构黄,架构周,架构吴,架构郑,架构孙,架构徐,架构马,架构朱,架构胡,架构林,架构郭,架构何,架构高,架构罗",
                "开发评委": "开发张,开发李,开发王,开发赵,开发陈,开发杨,开发黄,开发周,开发吴,开发郑,开发孙,开发徐,开发马,开发朱,开发胡,开发林,开发郭,开发何,开发高,开发罗",
                "测试评委": "测试张,测试李,测试王,测试赵,测试陈,测试杨,测试黄,测试周,测试吴,测试郑,测试孙,测试徐,测试马,测试朱,测试胡,测试林,测试郭,测试何,测试高,测试罗",
                "产品评委": "产品张,产品李,产品王,产品赵,产品陈,产品杨,产品黄,产品周,产品吴,产品郑,产品孙,产品徐,产品马,产品朱,产品胡,产品林,产品郭,产品何,产品高,产品罗"
            }
            
            # 保存配置文件
            with open(self.config_file, "w", encoding="utf-8") as f:
                config.write(f)
                
        except Exception as e:
            messagebox.showerror("配置错误", f"创建默认配置文件失败: {str(e)}")
    
    def create_widgets(self):
        """创建UI组件"""
        # 主框架
        # 修正父容器为对话框自身而非主窗口
        # 修复主框架父容器，使用主窗口作为父容器
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 标题
        ttk.Label(main_frame, text="POC评委名单抽签器", style="Header.TLabel").pack(pady=10)
        
        # 配置区域
        config_frame = ttk.LabelFrame(main_frame, text="抽签配置", padding="10")
        config_frame.pack(fill=tk.X, pady=5)
        
        # 项目选择
        ttk.Label(config_frame, text="选择项目:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.project_var = tk.StringVar()
        project_combo = ttk.Combobox(config_frame, textvariable=self.project_var, state="readonly", width=30)
        project_combo['values'] = self.projects
        if self.projects:
            self.project_var.set(self.projects[0])
        project_combo.grid(row=0, column=1, padx=5, pady=5)
        
        # 评委组选择
        ttk.Label(config_frame, text="选择评委组:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.role_group_var = tk.StringVar()
        role_group_combo = ttk.Combobox(config_frame, textvariable=self.role_group_var, state="readonly", width=15)
        
        # 创建键名到中文名称的映射
        self.role_group_display_names = {}
        display_values = []
        for key in self.role_groups.keys():
            if key == "3_roles":
                display_name = "3个评委"
            elif key == "5_roles":
                display_name = "5个评委"
            else:
                # 对于其他可能的配置，去掉"_roles"后缀并添加中文说明
                base_name = key.replace("_roles", "")
                display_name = f"{base_name}个评委"
            self.role_group_display_names[display_name] = key
            display_values.append(display_name)
        
        role_group_combo['values'] = display_values
        if self.role_groups:
            # 设置默认显示值
            first_key = next(iter(self.role_groups.keys()))
            for display_name, key in self.role_group_display_names.items():
                if key == first_key:
                    self.role_group_var.set(display_name)
                    break
            self.update_roles()  # 初始化角色列表
        
        # 修改绑定事件处理函数，从显示名称获取实际键名
        role_group_combo.bind("<<ComboboxSelected>>", lambda e: self.update_roles_from_display_name())
        role_group_combo.grid(row=0, column=3, padx=5, pady=5)
        
        # 操作按钮区域
        button_frame = ttk.Frame(main_frame, padding="10")
        button_frame.pack(fill=tk.X, pady=5)
        
        self.start_button = ttk.Button(button_frame, text="开始抽签", command=self.start_drawing)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="结束抽签", command=self.stop_drawing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.reset_button = ttk.Button(button_frame, text="重置抽签", command=self.reset_drawing)
        self.reset_button.pack(side=tk.LEFT, padx=5)
        
        self.save_button = ttk.Button(button_frame, text="保存抽签结果", command=self.save_results, state=tk.DISABLED)
        self.save_button.pack(side=tk.LEFT, padx=5)
        
        # 设置按钮
        self.settings_button = ttk.Button(button_frame, text="设置", command=self.open_settings)
        self.settings_button.pack(side=tk.RIGHT, padx=5)
        
        # 抽签结果显示区域
        result_frame = ttk.LabelFrame(main_frame, text="抽签结果", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 创建表格
        columns = ("role", "first_judge", "second_judge")
        self.result_tree = ttk.Treeview(result_frame, columns=columns, show="headings")
        
        # 设置列标题
        self.result_tree.heading("role", text="评委角色")
        self.result_tree.heading("first_judge", text="第1顺位评委")
        self.result_tree.heading("second_judge", text="第2顺位评委")
        
        # 设置列宽
        self.result_tree.column("role", width=150, anchor=tk.CENTER)
        self.result_tree.column("first_judge", width=200, anchor=tk.CENTER)
        self.result_tree.column("second_judge", width=200, anchor=tk.CENTER)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.result_tree.yview)
        self.result_tree.configure(yscroll=scrollbar.set)
        
        # 布局表格和滚动条
        self.result_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 状态区域
        status_frame = ttk.Frame(main_frame, padding="10")
        status_frame.pack(fill=tk.X, pady=5)
        
        self.status_var = tk.StringVar(value="等待抽签...")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT)
        
        self.time_var = tk.StringVar(value="抽签结束时间: --:--:--")
        ttk.Label(status_frame, textvariable=self.time_var).pack(side=tk.RIGHT)
        
        # 审计日志区域
        log_frame = ttk.LabelFrame(main_frame, text="操作日志", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_text = tk.Text(log_frame, height=15, width=100, state=tk.DISABLED, wrap=tk.WORD)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        log_scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.configure(yscroll=log_scrollbar.set)
        
        # 加载日志
        self.load_audit_log()
    
    def update_roles(self):
        """更新角色列表"""
        # 这个方法现在由 update_roles_from_display_name() 调用
        # 保留这个方法以保持向后兼容性
        selected_group = self.role_group_var.get()
        if selected_group in self.role_groups:
            self.current_roles = list(self.role_groups[selected_group].keys())
            # 清空之前的结果
            self.reset_drawing()
    
    def update_roles_from_display_name(self):
        """从中文显示名称更新角色列表"""
        display_name = self.role_group_var.get()
        # 通过映射获取实际的配置键名
        if display_name in self.role_group_display_names:
            selected_group = self.role_group_display_names[display_name]
            if selected_group in self.role_groups:
                self.current_roles = list(self.role_groups[selected_group].keys())
                # 清空之前的结果
                self.reset_drawing()
    
    def start_drawing(self):
        """开始抽签动画"""
        if self.drawing_in_progress:
            return
            
        selected_project = self.project_var.get()
        display_name = self.role_group_var.get()
        
        if not selected_project or not display_name:
            messagebox.showwarning("警告", "请选择项目和评委组")
            return
            
        # 获取实际的配置键名
        if display_name in self.role_group_display_names:
            selected_group = self.role_group_display_names[display_name]
        else:
            selected_group = display_name
            
        # 生成操作ID
        self.current_operation_id = str(uuid.uuid4())
        
        self.drawing_in_progress = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.DISABLED)
        self.status_var.set("正在抽签中...")
        
        # 清空之前的结果
        self.drawing_results = {}
        self.second_judges = {}
        for item in self.result_tree.get_children():
            self.result_tree.delete(item)
        
        # 记录开始日志
        self.log_audit(f"开始抽签 - 项目: {selected_project}, 评委组: {selected_group}", "INFO")
        
        # 开始抽签动画
        self.update_drawing()
    
    def update_drawing(self):
        """更新抽签动画"""
        if not self.drawing_in_progress:
            return
            
        display_name = self.role_group_var.get()
        # 获取实际的配置键名
        if display_name in self.role_group_display_names:
            selected_group = self.role_group_display_names[display_name]
        else:
            selected_group = display_name
        
        roles = self.role_groups.get(selected_group, {})
        
        # 为每个角色随机选择评委
        for role in roles:
            # 第一顺位评委
            first_judge = random.choice(roles[role])
            self.drawing_results[role] = first_judge
            
            # 第二顺位评委（确保与第一顺位不同）
            filtered_judges = [j for j in roles[role] if j != first_judge]
            second_judge = random.choice(filtered_judges) if filtered_judges else first_judge
            self.second_judges[role] = second_judge
        
        # 更新表格
        for item in self.result_tree.get_children():
            self.result_tree.delete(item)
            
        for role in sorted(self.drawing_results.keys()):
            self.result_tree.insert("", tk.END, values=(
                role, 
                self.drawing_results[role],
                self.second_judges[role]
            ))
        
        # 继续动画
        self.root.after(100, self.update_drawing)
    
    def stop_drawing(self):
        """停止抽签"""
        if not self.drawing_in_progress:
            return
            
        self.drawing_in_progress = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.NORMAL)
        
        # 更新状态和时间
        end_time = datetime.now().strftime("%H:%M:%S")
        self.status_var.set("抽签已结束")
        self.time_var.set(f"抽签结束时间: {end_time}")
        
        # 记录结束日志
        selected_project = self.project_var.get()
        self.log_audit(f"结束抽签 - 项目: {selected_project}, 时间: {end_time}", "INFO")
    
    def reset_drawing(self):
        """重置抽签结果"""
        self.drawing_in_progress = False
        self.drawing_results = {}
        self.second_judges = {}
        self.current_operation_id = None
        
        # 更新UI状态
        if hasattr(self, 'start_button'):
            self.start_button.config(state=tk.NORMAL)
        if hasattr(self, 'stop_button'):
            self.stop_button.config(state=tk.DISABLED)
        if hasattr(self, 'save_button'):
            self.save_button.config(state=tk.DISABLED)
        # 更新状态变量
        if hasattr(self, 'status_var'):
            self.status_var.set("等待抽签...")
        if hasattr(self, 'time_var'):
            self.time_var.set("抽签结束时间: --:--:--")
        
        # 清空结果表格
        if hasattr(self, 'result_tree'):
            for item in self.result_tree.get_children():
                self.result_tree.delete(item)
        
        # 记录重置日志
        if hasattr(self, 'log_text'):
            self.log_audit("重置抽签结果", "INFO")
    
    def save_results(self):
        """保存抽签结果到CSV文件"""
        if not self.drawing_results:
            messagebox.showwarning("警告", "没有可保存的抽签结果")
            return
            
        selected_project = self.project_var.get()
        display_name = self.role_group_var.get()  # 这是中文显示名称
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # 移除文件名中的非法字符
        safe_project = re.sub(r'[\\/:*?"<>|]', '', selected_project)
        safe_display = re.sub(r'[\\/:*?"<>|]', '', display_name)
        default_filename = f"评委抽签结果_{safe_project}_{safe_display}_{timestamp}.csv"
        
        # 询问保存路径
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV文件", "*.csv"), ("所有文件", "*.*")],
            initialfile=default_filename
        )
        
        if not file_path:
            return
            
        try:
            # 准备数据
            data = []
            for role in sorted(self.drawing_results.keys()):
                data.append({
                    "操作ID": self.current_operation_id,
                    "项目名称": selected_project,
                    "评委组": display_name,
                    "抽签时间": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "评委角色": role,
                    "第1顺位评委": self.drawing_results[role],
                    "第2顺位评委": self.second_judges[role]
                })
            
            # 写入CSV文件
            with open(file_path, "w", newline="", encoding="utf-8-sig") as f:
                fieldnames = ["操作ID", "项目名称", "评委组", "抽签时间", "评委角色", "第1顺位评委", "第2顺位评委"]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                
                writer.writeheader()
                for row in data:
                    writer.writerow(row)
            
            messagebox.showinfo("成功", f"抽签结果已保存至:\n{file_path}")
            self.log_audit(f"保存抽签结果至: {file_path}", "INFO")
            
        except Exception as e:
            messagebox.showerror("错误", f"保存文件失败: {str(e)}")
            self.log_audit(f"保存文件失败: {str(e)}", "ERROR")
    
    def log_audit(self, message, level="INFO"):
        """记录审计日志"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] [{level}] {message}\n"
            
            # 写入日志文件
            with open(self.audit_log_file, "a", encoding="utf-8") as f:
                f.write(log_entry)
            
            # 更新UI日志显示
            self.update_log_display(log_entry)
            
        except Exception as e:
            print(f"记录日志失败: {str(e)}")
    
    def update_log_display(self, message):
        """更新日志显示"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message)
        self.log_text.see(tk.END)  # 滚动到最后
        self.log_text.config(state=tk.DISABLED)
    
    def load_audit_log(self):
        """加载审计日志"""
        try:
            if os.path.exists(self.audit_log_file):
                with open(self.audit_log_file, "r", encoding="utf-8") as f:
                    # 只显示最后10行日志
                    lines = f.readlines()[-10:]
                    self.log_text.config(state=tk.NORMAL)
                    self.log_text.insert(tk.END, "".join(lines))
                    self.log_text.see(tk.END)
                    self.log_text.config(state=tk.DISABLED)
        except Exception as e:
            print(f"加载日志失败: {str(e)}")
    
    def open_settings(self):
        """打开设置窗口"""
        SettingsWindow(self.root, self)


class ConfigEditorDialog(tk.Toplevel):
    def __init__(self, parent, title, config_items):
        super().__init__(parent)
        self.title(title)
        # 设置对话框初始大小
        self.geometry("600x400")
        # 允许窗口调整大小
        self.resizable(True, True)
        # 设置初始窗口尺寸
        self.geometry("600x400")
        self.parent = parent
        self.result = None
        self.config_items = config_items.copy()  # 存储配置项列表 [(key, value), ...]
        self.selected_item = None
        
        # 设置窗口大小和位置
        self.geometry("600x400")
        self.transient(parent)
        self.grab_set()
        
        # 创建主框架
        main_frame = ttk.Frame(self, padding="10")
        main_frame.grid(row=0, column=0, sticky=tk.NSEW)
        # 配置对话框网格权重使内容可扩展
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        # 创建左侧列表区域和右侧操作区域
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        right_frame = ttk.Frame(main_frame, width=200)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)
        right_frame.pack_propagate(False)
        
        # 左侧列表区域
        list_label = ttk.Label(left_frame, text="配置项列表")
        list_label.pack(anchor=tk.W, pady=(0, 5))
        
        # 创建列表
        columns = ("key", "value")
        self.items_tree = ttk.Treeview(left_frame, columns=columns, show="headings", selectmode="browse")
        self.items_tree.heading("key", text="键")
        self.items_tree.heading("value", text="值")
        self.items_tree.column("key", width=150, anchor=tk.W)
        self.items_tree.column("value", width=200, anchor=tk.W)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.items_tree.yview)
        self.items_tree.configure(yscroll=scrollbar.set)
        
        # 布局列表和滚动条
        self.items_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 绑定列表事件
        self.items_tree.bind("<<TreeviewSelect>>", self.on_item_select)
        self.items_tree.bind("<Double-1>", lambda e: self.edit_item())
        
        # 右侧操作按钮
        button_width = 15
        ttk.Button(right_frame, text="新建(&N)", width=button_width, command=self.new_item).pack(fill=tk.X, pady=5)
        ttk.Button(right_frame, text="编辑(&E)", width=button_width, command=self.edit_item).pack(fill=tk.X, pady=5)
        ttk.Button(right_frame, text="删除(&D)", width=button_width, command=self.delete_item).pack(fill=tk.X, pady=5)
        ttk.Separator(right_frame).pack(fill=tk.X, pady=10)
        ttk.Button(right_frame, text="上移(&U)", width=button_width, command=self.move_up).pack(fill=tk.X, pady=5)
        ttk.Button(right_frame, text="下移(&O)", width=button_width, command=self.move_down).pack(fill=tk.X, pady=5)
        
        # 底部按钮
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=10)
        
        ttk.Button(bottom_frame, text="确定", command=self.on_ok).pack(side=tk.RIGHT, padx=5)
        ttk.Button(bottom_frame, text="取消", command=self.on_cancel).pack(side=tk.RIGHT, padx=5)
        
        # 确保Treeview创建后再加载数据
        # 使用after_idle确保控件初始化完成后再加载数据
        self.after_idle(self.refresh_list)
        
        # 等待窗口关闭
        self.wait_window(self)
        
    def refresh_list(self):
        """刷新列表显示"""
        # 清空现有项前检查控件是否存在
        if hasattr(self, 'items_tree') and self.items_tree.winfo_exists():
            for item in self.items_tree.get_children():
                self.items_tree.delete(item)
        
        # 添加配置项
        # 检查控件存在性后再添加项目
        if hasattr(self, 'items_tree') and self.items_tree.winfo_exists():
            for i, (key, value) in enumerate(self.config_items):
                self.items_tree.insert('', tk.END, values=(key, value), iid=str(i))
        
    def on_item_select(self, event):
        """选择列表项时触发"""
        selected = self.items_tree.selection()
        if selected:
            self.selected_item = int(selected[0])
        else:
            self.selected_item = None
        
    def new_item(self):
        """新建配置项"""
        dialog = KeyValueDialog(self, "新建配置项", "键名:", "值:")
        if dialog.result:
            key, value = dialog.result
            # 将换行符替换为逗号，确保INI格式兼容
            value = value.replace('\n', ',')
            # 验证键名合法性（不能包含=或:字符）
            if '=' in key or ':' in key:
                messagebox.showerror("错误", "键名不能包含=或:字符")
                return
            # 检查键是否已存在
            for k, v in self.config_items:
                if k == key:
                    messagebox.showerror("错误", f"键 '{key}' 已存在！")
                    return
            self.config_items.append((key, value))
            self.refresh_list()
            # 选中新添加的项
            self.items_tree.selection_set(str(len(self.config_items)-1))
            self.items_tree.focus_set(str(len(self.config_items)-1))
        
    def edit_item(self):
        """编辑选中的配置项"""
        if self.selected_item is None:
            messagebox.showinfo("提示", "请先选择要编辑的配置项")
            return
        
        current_key, current_value = self.config_items[self.selected_item]
        dialog = KeyValueDialog(self, "编辑配置项", "键名:", "值:", (current_key, current_value))
        if dialog.result:
            new_key, new_value = dialog.result
            # 将换行符替换为逗号，确保INI格式兼容
            new_value = new_value.replace('\n', ',')
            # 验证键名合法性（不能包含=或:字符）
            if '=' in new_key or ':' in new_key:
                messagebox.showerror("错误", "键名不能包含=或:字符")
                return
            # 检查键是否已存在（排除当前项）
            for i, (k, v) in enumerate(self.config_items):
                if i != self.selected_item and k == new_key:
                    messagebox.showerror("错误", f"键 '{new_key}' 已存在！")
                    return
            self.config_items[self.selected_item] = (new_key, new_value)
            self.refresh_list()
            # 重新选中编辑后的项
            self.items_tree.selection_set(str(self.selected_item))
            self.items_tree.focus_set(str(self.selected_item))
        
    def delete_item(self):
        """删除选中的配置项"""
        if self.selected_item is None:
            messagebox.showinfo("提示", "请先选择要删除的配置项")
            return
        
        key, value = self.config_items[self.selected_item]
        if messagebox.askyesno("确认", f"确定要删除 '{key}' 吗？"):
            del self.config_items[self.selected_item]
            self.selected_item = None
            self.refresh_list()
        
    def move_up(self):
        """上移选中的配置项"""
        if self.selected_item is None or self.selected_item == 0:
            return
        
        # 交换位置
        (self.config_items[self.selected_item], self.config_items[self.selected_item-1]) = (
            self.config_items[self.selected_item-1], self.config_items[self.selected_item]
        )
        
        # 更新列表
        new_index = self.selected_item - 1
        self.refresh_list()
        self.selected_item = new_index
        self.items_tree.selection_set(str(new_index))
        self.items_tree.focus_set(str(new_index))
        
    def move_down(self):
        """下移选中的配置项"""
        if self.selected_item is None or self.selected_item >= len(self.config_items)-1:
            return
        
        # 交换位置
        self.config_items[self.selected_item], self.config_items[self.selected_item+1] = self.config_items[self.selected_item+1], self.config_items[self.selected_item]
        
        # 更新列表
        new_index = self.selected_item + 1
        self.refresh_list()
        self.selected_item = new_index
        self.items_tree.selection_set(str(new_index))
        self.items_tree.focus_set(str(new_index))
        
    def on_ok(self):
        """确定按钮回调"""
        self.result = self.config_items
        
    def on_cancel(self):
        """取消按钮回调"""
        # 保持配置管理窗口打开，仅关闭当前编辑对话框
        self.destroy()

class KeyValueDialog(tk.Toplevel):
    """用于新建/编辑单个键值对的简单对话框"""
    def __init__(self, parent, title, key_label, value_label, key_value=None):
        super().__init__(parent)
        # 允许对话框调整大小以显示完整内容
        self.resizable(True, True)
        # 设置初始窗口尺寸以确保内容可见
        self.geometry("600x400")
        self.title(title)
        self.parent = parent
        self.result = None
        
        # 创建界面元素
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text=key_label).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.key_entry = ttk.Entry(main_frame, width=30)
        self.key_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(main_frame, text=value_label).grid(row=1, column=0, padx=5, pady=5, sticky=tk.NW)
        # 增加文本框尺寸以显示更多内容
        # 启用文本自动换行以显示完整内容
        self.value_entry = tk.Text(main_frame, width=50, height=10, wrap=tk.WORD)
        # 配置网格权重使文本框可随窗口调整大小
        main_frame.grid_rowconfigure(1, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)
        self.value_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.NSEW)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(main_frame, command=self.value_entry.yview)
        scrollbar.grid(row=1, column=2, sticky=tk.NS)
        self.value_entry.config(yscrollcommand=scrollbar.set)
        # 配置网格权重使文本框可随窗口调整大小
        main_frame.grid_rowconfigure(1, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)
        
        # 设置网格权重使文本框可扩展
        main_frame.grid_rowconfigure(1, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)
        
        # 如果提供了初始值，则填充
        if key_value:
            # 确保键名正确显示
            self.key_entry.insert(0, key_value[0] if key_value[0] else '')
            # 处理值显示（支持空值）
            # 确保value_content为字符串，处理可能的None值
            value_content = key_value[1] if (len(key_value) > 1 and key_value[1] is not None) else ''
            # 移除值内容为空的判断，确保即使为空也能显示
            # 处理空值显示问题
            # 确保值正确显示，处理空值和类型问题
            # 简化显示值生成逻辑
            # 处理None值并替换分隔符（现在使用逗号作为分隔符）
            display_value = (value_content or '').replace(',', '\n')
            # 为空值显示空白行
            # 为空值显示空白行，确保值可见
            self.value_entry.insert(tk.END, display_value if display_value else '\n')
            self.key_entry.focus_set()
        
        # 按钮区域
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="确定", command=self.on_ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="取消", command=self.on_cancel).pack(side=tk.LEFT, padx=5)
        
        # 设置模态窗口
        self.grab_set()
        self.wait_window(self)
        
    def on_ok(self):
        key = self.key_entry.get().strip()
        # 获取所有文本行并按逗号连接
        # 使用end-1c排除文本框自动添加的尾随换行符
        value_text = self.value_entry.get("1.0", "end-1c").strip()
        value_lines = [line.strip() for line in value_text.split('\n') if line.strip()]
        value = ','.join(value_lines)
        if key:
            self.result = (key, value)
        self.destroy()
        
    def on_cancel(self):
        self.destroy()

class SettingsWindow(tk.Toplevel):
    def __init__(self, parent, main_app):
        super().__init__(parent)
        self.main_app = main_app
        self.main_app.load_config()  # 刷新配置
        self.title("配置管理")
        self.geometry("700x500")
        self.transient(parent)
        self.grab_set()
        
        # 设置中文字体
        self.style = ttk.Style()
        self.style.configure("TLabel", font=("SimHei", 10))
        self.style.configure("TButton", font=("SimHei", 10))
        self.style.configure("TCombobox", font=("SimHei", 10))
        
        self.create_widgets()
        
    def create_widgets(self):
        """创建设置窗口组件"""
        # 主框架
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 配置项选择区域
        config_frame = ttk.LabelFrame(main_frame, text="配置项", padding="10")
        config_frame.pack(fill=tk.X, pady=5)
        
        # 配置节选择
        ttk.Label(config_frame, text="选择配置名:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.section_var = tk.StringVar()
        section_combo = ttk.Combobox(config_frame, textvariable=self.section_var, state="readonly", width=20)
        self.sections = self.main_app.config.sections()
        section_combo['values'] = self.sections
        section_combo.bind("<<ComboboxSelected>>", lambda e: self.update_config_items())
        section_combo.grid(row=0, column=1, padx=5, pady=5)
        
        # 添加新配置节按钮
        ttk.Button(config_frame, text="添加配置名", command=self.add_section).grid(row=0, column=2, padx=5, pady=5)
        
        # 删除配置节按钮
        ttk.Button(config_frame, text="删除配置名", command=self.delete_section).grid(row=0, column=3, padx=5, pady=5)
        
        # 配置项列表
        items_frame = ttk.LabelFrame(main_frame, text="配置项列表", padding="10")
        items_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 创建表格
        columns = ("key", "value")
        self.items_tree = ttk.Treeview(items_frame, columns=columns, show="headings")
        
        # 设置列标题
        self.items_tree.heading("key", text="键")
        self.items_tree.heading("value", text="值")
        
        # 设置列宽
        self.items_tree.column("key", width=150, anchor=tk.W)
        self.items_tree.column("value", width=400, anchor=tk.W)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(items_frame, orient=tk.VERTICAL, command=self.items_tree.yview)
        self.items_tree.configure(yscroll=scrollbar.set)
        
        # 布局表格和滚动条
        self.items_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 绑定双击事件到编辑功能
        self.items_tree.bind("<Double-1>", lambda event: self.edit_config_item())
        
        # 初始化配置项列表
        if self.sections:
            self.section_var.set(self.sections[0])
            # 延迟加载配置项，确保Treeview已创建
            self.after_idle(self.update_config_items)
        
        # 按钮区域
        button_frame = ttk.Frame(main_frame, padding="10")
        button_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(button_frame, text="添加配置项", command=self.add_config_item).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="编辑配置项", command=self.edit_config_item).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="删除配置项", command=self.delete_config_item).pack(side=tk.LEFT, padx=5)
        
        # 底部按钮
        bottom_frame = ttk.Frame(main_frame, padding="10")
        bottom_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(bottom_frame, text="保存配置", command=self.save_config).pack(side=tk.RIGHT, padx=5)
        ttk.Button(bottom_frame, text="取消", command=self.destroy).pack(side=tk.RIGHT, padx=5)
    
    def update_config_items(self):
        """更新配置项列表"""
        selected_section = self.section_var.get()
        if not selected_section:
            return
        # 验证配置节是否存在
        if not self.main_app.config.has_section(selected_section):
            messagebox.showerror("错误", f"配置节 '{selected_section}' 不存在")
            return
            
        # 重新加载配置以确保获取最新值
        self.main_app.load_config()
            
        # 检查items_tree属性是否存在
        if not hasattr(self, 'items_tree'):
            return
            
        # 清空现有项前检查控件是否存在
        if hasattr(self, 'items_tree') and self.items_tree.winfo_exists():
            for item in self.items_tree.get_children():
                self.items_tree.delete(item)
            
        # 填充表格
        try:
            for key, value in self.main_app.config.items(selected_section):
                self.items_tree.insert("", tk.END, values=(key, value))
        except Exception as e:
            messagebox.showerror("错误", f"加载配置项失败: {str(e)}")
    
    def add_section(self):
        """添加新配置节"""
        section_name = simpledialog.askstring("添加配置节", "请输入配置节名称:")
        if not section_name:
            return
        # 验证配置节名称合法性（不能包含[]字符）
        if '[' in section_name or ']' in section_name:
            messagebox.showerror("错误", "配置节名称不能包含[或]字符")
            return
            
        if section_name in self.main_app.config.sections():
            messagebox.showwarning("警告", f"配置节 '{section_name}' 已存在")
            return
            
        # 添加新配置节
        self.main_app.config.add_section(section_name)
        self.sections = self.main_app.config.sections()
        self.section_var.set(section_name)
        
        # 更新下拉框
        section_combo = self.nametowidget(".!settingswindow.!frame.!labelframe.!combobox")
        section_combo['values'] = self.sections
        
        # 清空配置项列表
        for item in self.items_tree.get_children():
            self.items_tree.delete(item)
    
    def delete_section(self):
        """删除配置节"""
        selected_section = self.section_var.get()
        if not selected_section:
            return
            
        # 确认删除
        if messagebox.askyesno("确认删除", f"确定要删除配置节 '{selected_section}' 吗?\n此操作不可恢复!"):
            try:
                self.main_app.config.remove_section(selected_section)
                self.sections = self.main_app.config.sections()
                
                # 更新下拉框
                section_combo = self.nametowidget(".!settingswindow.!frame.!labelframe.!combobox")
                section_combo['values'] = self.sections
                
                # 选择第一个配置节
                if self.sections:
                    self.section_var.set(self.sections[0])
                    self.update_config_items()
                else:
                    # 清空配置项列表
                    for item in self.items_tree.get_children():
                        self.items_tree.delete(item)
                        
            except Exception as e:
                messagebox.showerror("错误", f"删除配置节失败: {str(e)}")
    
    def add_config_item(self):
        """添加配置项"""
        selected_section = self.section_var.get()
        if not selected_section:
            messagebox.showwarning("警告", "请先选择一个配置节")
            return
            
        # 获取键和值
        dialog = KeyValueDialog(self, "添加配置项", "键名:", "值:")
        if not dialog.result:
            return
        key, value = dialog.result
            
        if self.main_app.config.has_option(selected_section, key):
            messagebox.showwarning("警告", f"键 '{key}' 已存在")
            return
            
        # 添加配置项
        self.main_app.config.set(selected_section, key, value)
        self.items_tree.insert("", tk.END, values=(key, value))
    
    def edit_config_item(self):
        """编辑配置项"""
        selected_section = self.section_var.get()
        if not selected_section:
            messagebox.showwarning("警告", "请先选择一个配置节")
            return
            
        # 获取选中的项
        selected_items = self.items_tree.selection()
        if not selected_items:
            messagebox.showwarning("警告", "请先选择一个配置项")
            return
            
        # 获取当前值
        item = selected_items[0]
        current_key, current_value = self.items_tree.item(item, "values")
        
        # 输入新值
        dialog = KeyValueDialog(self, "编辑配置项", "键名:", "值:", (current_key, current_value))
        if not dialog.result:
            return
        new_key, new_value = dialog.result
            
        # 如果键名改变，先删除旧键
        if new_key != current_key:
            self.main_app.config.remove_option(selected_section, current_key)
        # 更新配置值
        self.main_app.config.set(selected_section, new_key, new_value)
        # 保存配置
        self.save_config()
        # 刷新配置项列表
        self.update_config_items()
        
        # 设置新值
        self.main_app.config.set(selected_section, new_key, new_value)
        

    
    def delete_config_item(self):
        """删除配置项"""
        selected_section = self.section_var.get()
        if not selected_section:
            messagebox.showwarning("警告", "请先选择一个配置节")
            return
            
        # 获取选中的项
        selected_items = self.items_tree.selection()
        if not selected_items:
            messagebox.showwarning("警告", "请先选择一个配置项")
            return
            
        # 确认删除
        if messagebox.askyesno("确认删除", "确定要删除选中的配置项吗?"):
            item = selected_items[0]
            key, _ = self.items_tree.item(item, "values")
            
            # 删除配置项
            self.main_app.config.remove_option(selected_section, key)
            
            # 从表格中删除
            self.items_tree.delete(item)
    
    def save_config(self):
        """保存配置"""
        try:
            # 验证必要的配置项是否存在
            if not self.main_app.config.has_section('projects'):
                messagebox.showerror("错误", "配置缺少必要的'projects'节")
                return
            if not self.main_app.config.has_option('projects', 'project_list'):
                messagebox.showerror("错误", "配置缺少必要的'project_list'键")
                return
            # 验证project_list格式是否正确
            project_list = self.main_app.config.get('projects', 'project_list')
            if not project_list.strip():
                messagebox.showerror("错误", "project_list不能为空")
                return
            # 验证至少存在一个评委组配置节
            role_group_sections = [s for s in self.main_app.config.sections() if s.endswith("_roles")]
            if not role_group_sections:
                messagebox.showerror("错误", "配置缺少必要的评委组节（以_roles结尾）")
                return
            with open(self.main_app.config_file, "w", encoding="utf-8") as f:
                self.main_app.config.write(f)
            
            messagebox.showinfo("成功", "配置已保存")
            # 先更新主窗口下拉框再关闭设置窗口
            # 使用after_idle确保messagebox关闭后再执行
            self.after_idle(lambda: self.main_app.refresh_ui())
            self.after_idle(self.destroy)
            
        except Exception as e:
            messagebox.showerror("错误", f"保存配置失败: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = POCJudgeSelector(root)
    root.mainloop()
    