import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import configparser
import random
import csv
import os
import uuid
from datetime import datetime
import json
import re
import sqlite3
from sqlite3 import Error

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
        
        # 数据库相关
        self.db_file = "drawing_results.db"
        
        # 加载配置
        self.config = configparser.ConfigParser()
        self.load_config()
        
        # 初始化数据库
        self.init_database()
        
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
    
    def init_database(self):
        """初始化数据库连接并创建表"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # 创建抽签结果表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS drawing_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation_id TEXT NOT NULL,
                    project_name TEXT NOT NULL,
                    role_group TEXT NOT NULL,
                    draw_time TEXT NOT NULL,
                    judge_role TEXT NOT NULL,
                    first_judge TEXT NOT NULL,
                    second_judge TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
        except Error as e:
            print(f"数据库初始化错误: {e}")
            messagebox.showerror("数据库错误", f"初始化数据库失败: {str(e)}")
    
    def get_recent_winning_judges(self, role, limit=2):
        """获取最近中签的评委
        
        Args:
            role: 评委角色
            limit: 返回最近中签的数量，默认2个
            
        Returns:
            最近中签的评委列表
        """
        recent_judges = []
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # 查询最近中签的评委
            cursor.execute('''
                SELECT first_judge FROM drawing_results 
                WHERE judge_role = ? 
                ORDER BY draw_time DESC 
                LIMIT ?
            ''', (role, limit))
            
            for row in cursor.fetchall():
                recent_judges.append(row[0])
            
            conn.close()
        except Error as e:
            print(f"查询最近中签评委错误: {e}")
        
        return recent_judges
    
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
        
        # 数据库管理按钮
        self.db_button = ttk.Button(button_frame, text="数据管理", command=self.open_database_management)
        self.db_button.pack(side=tk.RIGHT, padx=5)
        
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
            # 获取所有可用评委
            all_judges = roles[role]
            
            # 获取最近两次中签的评委
            recent_winners = self.get_recent_winning_judges(role)
            
            # 过滤掉最近两次中签的评委
            available_judges = [j for j in all_judges if j not in recent_winners]
            
            # 如果所有评委都被过滤掉了（这种情况极少发生），则使用全部评委
            if not available_judges:
                available_judges = all_judges
            
            # 第一顺位评委
            first_judge = random.choice(available_judges)
            self.drawing_results[role] = first_judge
            
            # 第二顺位评委（确保与第一顺位不同）
            filtered_judges = [j for j in available_judges if j != first_judge]
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
        """停止抽签并保存结果到数据库"""
        if not self.drawing_in_progress:
            return
            
        self.drawing_in_progress = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.NORMAL)
        
        # 更新状态和时间
        end_time = datetime.now().strftime("%H:%M:%S")
        draw_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.status_var.set("抽签已结束")
        self.time_var.set(f"抽签结束时间: {end_time}")
        
        # 记录结束日志
        selected_project = self.project_var.get()
        display_name = self.role_group_var.get()
        selected_group = self.role_group_display_names.get(display_name, display_name)
        self.log_audit(f"结束抽签 - 项目: {selected_project}, 时间: {end_time}", "INFO")
        
        # 保存抽签结果到数据库
        self.save_results_to_database(selected_project, selected_group, draw_time)
    
    def save_results_to_database(self, project_name, role_group, draw_time):
        """保存抽签结果到数据库
        
        Args:
            project_name: 项目名称
            role_group: 评委组
            draw_time: 抽签时间
        """
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # 保存每个角色的抽签结果
            for role in self.drawing_results:
                cursor.execute('''
                    INSERT INTO drawing_results 
                    (operation_id, project_name, role_group, draw_time, judge_role, first_judge, second_judge)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (self.current_operation_id, project_name, role_group, draw_time, 
                      role, self.drawing_results[role], self.second_judges[role]))
            
            conn.commit()
            conn.close()
            
            self.log_audit(f"抽签结果已保存到数据库 - 项目: {project_name}", "INFO")
            
        except Error as e:
            error_msg = f"保存抽签结果到数据库失败: {str(e)}"
            print(error_msg)
            messagebox.showerror("数据库错误", error_msg)
            self.log_audit(error_msg, "ERROR")
    
    def query_drawing_results(self, project_name=None, role_group=None, start_time=None, end_time=None):
        """查询抽签结果
        
        Args:
            project_name: 项目名称（可选）
            role_group: 评委组（可选）
            start_time: 开始时间（可选）
            end_time: 结束时间（可选）
            
        Returns:
            查询结果列表
        """
        results = []
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # 构建查询语句
            query = "SELECT * FROM drawing_results WHERE 1=1"
            params = []
            
            if project_name:
                query += " AND project_name = ?"
                params.append(project_name)
            
            if role_group:
                query += " AND role_group = ?"
                params.append(role_group)
            
            if start_time:
                query += " AND draw_time >= ?"
                params.append(start_time)
            
            if end_time:
                query += " AND draw_time <= ?"
                params.append(end_time)
            
            query += " ORDER BY draw_time DESC"
            
            cursor.execute(query, params)
            results = cursor.fetchall()
            conn.close()
            
        except Error as e:
            print(f"查询抽签结果错误: {e}")
            messagebox.showerror("数据库错误", f"查询抽签结果失败: {str(e)}")
        
        return results
    
    def update_drawing_result(self, result_id, first_judge=None, second_judge=None):
        """修改抽签结果
        
        Args:
            result_id: 结果ID
            first_judge: 第一顺位评委（可选）
            second_judge: 第二顺位评委（可选）
            
        Returns:
            是否修改成功
        """
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # 构建更新语句
            query = "UPDATE drawing_results SET "
            params = []
            
            if first_judge is not None:
                query += "first_judge = ?"
                params.append(first_judge)
                if second_judge is not None:
                    query += ", second_judge = ?"
                    params.append(second_judge)
            elif second_judge is not None:
                query += "second_judge = ?"
                params.append(second_judge)
            else:
                conn.close()
                return False
            
            query += " WHERE id = ?"
            params.append(result_id)
            
            cursor.execute(query, params)
            conn.commit()
            conn.close()
            
            self.log_audit(f"修改抽签结果ID: {result_id}", "INFO")
            return True
            
        except Error as e:
            error_msg = f"修改抽签结果失败: {str(e)}"
            print(error_msg)
            messagebox.showerror("数据库错误", error_msg)
            self.log_audit(error_msg, "ERROR")
            return False
    
    def delete_drawing_result(self, result_id):
        """删除抽签结果
        
        Args:
            result_id: 结果ID
            
        Returns:
            是否删除成功
        """
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # 获取要删除的记录信息用于日志
            cursor.execute("SELECT project_name, draw_time FROM drawing_results WHERE id = ?", (result_id,))
            record = cursor.fetchone()
            
            # 删除记录
            cursor.execute("DELETE FROM drawing_results WHERE id = ?", (result_id,))
            conn.commit()
            conn.close()
            
            if record:
                self.log_audit(f"删除抽签结果ID: {result_id}, 项目: {record[0]}, 时间: {record[1]}", "INFO")
            else:
                self.log_audit(f"删除抽签结果ID: {result_id} (记录不存在)", "INFO")
                
            return True
            
        except Error as e:
            error_msg = f"删除抽签结果失败: {str(e)}"
            print(error_msg)
            messagebox.showerror("数据库错误", error_msg)
            self.log_audit(error_msg, "ERROR")
            return False
    
    def open_database_management(self):
        """打开数据库管理窗口"""
        # 创建数据库管理窗口
        db_window = tk.Toplevel(self.root)
        db_window.title("抽签结果管理")
        db_window.geometry("900x600")
        db_window.resizable(True, True)
        
        # 获取现有项目名称和评委组数据
        def get_existing_values():
            projects = set()
            role_groups = set()
            try:
                conn = sqlite3.connect('drawing_results.db')
                cursor = conn.cursor()
                cursor.execute("SELECT DISTINCT project_name, role_group FROM drawing_results")
                rows = cursor.fetchall()
                for row in rows:
                    if row[0]:
                        projects.add(row[0])
                    if row[1]:
                        role_groups.add(row[1])
                conn.close()
            except sqlite3.Error as e:
                print(f"获取数据失败: {str(e)}")
            return sorted(list(projects)), sorted(list(role_groups))
        
        # 查询条件区域
        search_frame = ttk.LabelFrame(db_window, text="查询条件", padding="10")
        search_frame.pack(fill=tk.X, pady=5)
        
        # 获取现有数据
        projects, role_groups = get_existing_values()
        
        # 项目名称下拉框 - 第一行
        ttk.Label(search_frame, text="项目名称:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        project_var = tk.StringVar()
        project_combobox = ttk.Combobox(search_frame, textvariable=project_var, width=18, values=projects)
        project_combobox.grid(row=0, column=1, padx=5, pady=5)
        project_combobox['state'] = 'readonly'  # 设置为只读模式
        
        # 评委组下拉框 - 第一行
        ttk.Label(search_frame, text="评委组:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        role_group_var = tk.StringVar()
        role_group_combobox = ttk.Combobox(search_frame, textvariable=role_group_var, width=18, values=role_groups)
        role_group_combobox.grid(row=0, column=3, padx=5, pady=5)
        role_group_combobox['state'] = 'readonly'  # 设置为只读模式
        
        # 日期时间选择函数
        def create_datetime_selector(parent, default_datetime):
            # 创建一个可以点击的输入框
            datetime_var = tk.StringVar(value=default_datetime)
            datetime_entry = ttk.Entry(parent, textvariable=datetime_var, width=20)
            
            # 日期时间选择窗口
            def open_datetime_picker():
                # 解析当前时间值
                try:
                    current_dt = datetime.strptime(datetime_var.get(), "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    current_dt = datetime.now()
                
                # 创建选择窗口
                picker_window = tk.Toplevel(parent)
                picker_window.title("选择日期时间")
                picker_window.geometry("350x200")
                picker_window.resizable(False, False)
                picker_window.transient(parent)
                picker_window.grab_set()
                
                # 计算窗口位置，显示在输入框下方
                entry_x, entry_y = datetime_entry.winfo_rootx(), datetime_entry.winfo_rooty()
                entry_height = datetime_entry.winfo_height()
                # 设置窗口位置在输入框的正下方
                picker_window.geometry(f"+{entry_x}+{entry_y + entry_height}")
                
                # 年下拉框
                ttk.Label(picker_window, text="年:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
                year_var = tk.StringVar(value=str(current_dt.year))
                year_values = [str(year) for year in range(2023, 2100)]
                year_combo = ttk.Combobox(picker_window, textvariable=year_var, values=year_values, width=6)
                year_combo.grid(row=0, column=1, padx=5, pady=5)
                
                # 月下拉框
                ttk.Label(picker_window, text="月:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
                month_var = tk.StringVar(value=str(current_dt.month).zfill(2))
                month_values = [str(month).zfill(2) for month in range(1, 13)]
                month_combo = ttk.Combobox(picker_window, textvariable=month_var, values=month_values, width=4)
                month_combo.grid(row=0, column=3, padx=5, pady=5)
                
                # 日下拉框
                ttk.Label(picker_window, text="日:").grid(row=0, column=4, padx=5, pady=5, sticky=tk.W)
                day_var = tk.StringVar(value=str(current_dt.day).zfill(2))
                # 根据年月更新日的选项
                def update_days():
                    year = int(year_var.get())
                    month = int(month_var.get())
                    # 计算该月的天数
                    if month in [4, 6, 9, 11]:
                        days_in_month = 30
                    elif month == 2:
                        # 判断闰年
                        if (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0):
                            days_in_month = 29
                        else:
                            days_in_month = 28
                    else:
                        days_in_month = 31
                    day_values = [str(day).zfill(2) for day in range(1, days_in_month + 1)]
                    day_combo['values'] = day_values
                    # 如果当前选中的日大于该月的天数，则调整为最后一天
                    current_day = int(day_var.get())
                    if current_day > days_in_month:
                        day_var.set(str(days_in_month).zfill(2))
                
                day_combo = ttk.Combobox(picker_window, textvariable=day_var, width=4)
                day_combo.grid(row=0, column=5, padx=5, pady=5)
                update_days()
                
                # 绑定年月变化事件
                year_combo.bind("<<ComboboxSelected>>", lambda e: update_days())
                month_combo.bind("<<ComboboxSelected>>", lambda e: update_days())
                
                # 时下拉框
                ttk.Label(picker_window, text="时:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
                hour_var = tk.StringVar(value=str(current_dt.hour).zfill(2))
                hour_values = [str(hour).zfill(2) for hour in range(0, 24)]
                hour_combo = ttk.Combobox(picker_window, textvariable=hour_var, values=hour_values, width=4)
                hour_combo.grid(row=1, column=1, padx=5, pady=5)
                
                # 分下拉框
                ttk.Label(picker_window, text="分:").grid(row=1, column=2, padx=5, pady=5, sticky=tk.W)
                minute_var = tk.StringVar(value=str(current_dt.minute).zfill(2))
                minute_values = [str(minute).zfill(2) for minute in range(0, 60)]
                minute_combo = ttk.Combobox(picker_window, textvariable=minute_var, values=minute_values, width=4)
                minute_combo.grid(row=1, column=3, padx=5, pady=5)
                
                # 秒下拉框
                ttk.Label(picker_window, text="秒:").grid(row=1, column=4, padx=5, pady=5, sticky=tk.W)
                second_var = tk.StringVar(value=str(current_dt.second).zfill(2))
                second_values = [str(second).zfill(2) for second in range(0, 60)]
                second_combo = ttk.Combobox(picker_window, textvariable=second_var, values=second_values, width=4)
                second_combo.grid(row=1, column=5, padx=5, pady=5)
                
                # 确定按钮
                def confirm_selection():
                    selected_datetime = f"{year_var.get()}-{month_var.get()}-{day_var.get()} {hour_var.get()}:{minute_var.get()}:{second_var.get()}"
                    datetime_var.set(selected_datetime)
                    picker_window.destroy()
                
                # 取消按钮
                def cancel_selection():
                    picker_window.destroy()
                
                # 按钮布局
                button_frame = ttk.Frame(picker_window)
                button_frame.grid(row=2, column=0, columnspan=6, pady=10)
                
                ttk.Button(button_frame, text="确定", command=confirm_selection).pack(side=tk.LEFT, padx=10)
                ttk.Button(button_frame, text="取消", command=cancel_selection).pack(side=tk.LEFT, padx=10)
            
            # 绑定点击事件
            datetime_entry.bind("<Button-1>", lambda e: open_datetime_picker())
            
            return datetime_entry, datetime_var
        
        # 开始时间输入 - 第二行
        ttk.Label(search_frame, text="开始时间:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        start_time_entry, start_time_var = create_datetime_selector(search_frame, "2023-01-01 00:00:00")
        start_time_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # 结束时间输入 - 第二行
        ttk.Label(search_frame, text="结束时间:").grid(row=1, column=2, padx=5, pady=5, sticky=tk.W)
        end_time_entry, end_time_var = create_datetime_selector(search_frame, datetime.now().strftime("%Y-%m-%d 23:59:59"))
        end_time_entry.grid(row=1, column=3, padx=5, pady=5)
        
        # 刷新下拉框数据
        def refresh_combobox_data():
            nonlocal projects, role_groups
            projects, role_groups = get_existing_values()
            project_combobox['values'] = projects
            role_group_combobox['values'] = role_groups
        
        # 查询按钮和刷新按钮 - 第三行
        buttons_frame = ttk.Frame(search_frame)
        buttons_frame.grid(row=2, column=0, columnspan=4, pady=5, sticky=tk.W)
        
        # 查询按钮
        def on_query():
            # 获取查询条件
            project = project_var.get().strip() if project_var.get().strip() else None
            role_group = role_group_var.get().strip() if role_group_var.get().strip() else None
            start_time = start_time_var.get().strip() if start_time_var.get().strip() else None
            end_time = end_time_var.get().strip() if end_time_var.get().strip() else None
            
            # 查询数据
            results = self.query_drawing_results(project, role_group, start_time, end_time)
            
            # 清空表格
            for item in result_tree.get_children():
                result_tree.delete(item)
            
            # 填充表格
            for row in results:
                result_tree.insert("", tk.END, values=row)
        
        query_button = ttk.Button(buttons_frame, text="查询", command=on_query)
        query_button.pack(side=tk.LEFT, padx=5)
        
        # 刷新数据按钮
        refresh_button = ttk.Button(buttons_frame, text="刷新数据", command=refresh_combobox_data)
        refresh_button.pack(side=tk.LEFT, padx=5)
        
        # 结果显示表格
        result_frame = ttk.LabelFrame(db_window, text="抽签结果", padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 创建表格
        columns = ("id", "operation_id", "project_name", "role_group", "draw_time", "judge_role", "first_judge", "second_judge")
        result_tree = ttk.Treeview(result_frame, columns=columns, show="headings")
        
        # 设置列标题和宽度
        result_tree.heading("id", text="ID")
        result_tree.heading("operation_id", text="操作ID")
        result_tree.heading("project_name", text="项目名称")
        result_tree.heading("role_group", text="评委组")
        result_tree.heading("draw_time", text="抽签时间")
        result_tree.heading("judge_role", text="评委角色")
        result_tree.heading("first_judge", text="第一顺位评委")
        result_tree.heading("second_judge", text="第二顺位评委")
        
        result_tree.column("id", width=50, anchor=tk.CENTER)
        result_tree.column("operation_id", width=100, anchor=tk.CENTER)
        result_tree.column("project_name", width=150, anchor=tk.CENTER)
        result_tree.column("role_group", width=100, anchor=tk.CENTER)
        result_tree.column("draw_time", width=150, anchor=tk.CENTER)
        result_tree.column("judge_role", width=100, anchor=tk.CENTER)
        result_tree.column("first_judge", width=120, anchor=tk.CENTER)
        result_tree.column("second_judge", width=120, anchor=tk.CENTER)
        
        # 添加滚动条
        y_scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=result_tree.yview)
        x_scrollbar = ttk.Scrollbar(result_frame, orient=tk.HORIZONTAL, command=result_tree.xview)
        result_tree.configure(yscroll=y_scrollbar.set, xscroll=x_scrollbar.set)
        
        # 布局表格和滚动条
        result_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        x_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # 操作按钮区域
        action_frame = ttk.Frame(db_window, padding="10")
        action_frame.pack(fill=tk.X, pady=5)
        
        # 修改按钮
        def on_update():
            selected_item = result_tree.selection()
            if not selected_item:
                messagebox.showwarning("警告", "请选择要修改的记录")
                return
            
            item = selected_item[0]
            values = result_tree.item(item, "values")
            result_id = values[0]
            
            # 创建修改窗口
            update_window = tk.Toplevel(db_window)
            update_window.title("修改抽签结果")
            update_window.geometry("400x200")
            
            # 第一顺位评委输入
            ttk.Label(update_window, text="第一顺位评委:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
            first_judge_var = tk.StringVar(value=values[6])
            first_judge_entry = ttk.Entry(update_window, textvariable=first_judge_var, width=30)
            first_judge_entry.grid(row=0, column=1, padx=10, pady=10)
            
            # 第二顺位评委输入
            ttk.Label(update_window, text="第二顺位评委:").grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
            second_judge_var = tk.StringVar(value=values[7])
            second_judge_entry = ttk.Entry(update_window, textvariable=second_judge_var, width=30)
            second_judge_entry.grid(row=1, column=1, padx=10, pady=10)
            
            # 确认修改按钮
            def confirm_update():
                first_judge = first_judge_var.get().strip()
                second_judge = second_judge_var.get().strip()
                
                if not first_judge:
                    messagebox.showwarning("警告", "第一顺位评委不能为空")
                    return
                
                if self.update_drawing_result(result_id, first_judge, second_judge):
                    # 更新表格
                    new_values = list(values)
                    new_values[6] = first_judge
                    new_values[7] = second_judge
                    result_tree.item(item, values=new_values)
                    update_window.destroy()
                    messagebox.showinfo("成功", "修改成功")
            
            # 按钮
            ttk.Button(update_window, text="确认", command=confirm_update).grid(row=2, column=0, padx=10, pady=20)
            ttk.Button(update_window, text="取消", command=update_window.destroy).grid(row=2, column=1, padx=10, pady=20)
        
        update_button = ttk.Button(action_frame, text="修改", command=on_update)
        update_button.pack(side=tk.LEFT, padx=5)
        
        # 删除按钮
        def on_delete():
            selected_item = result_tree.selection()
            if not selected_item:
                messagebox.showwarning("警告", "请选择要删除的记录")
                return
            
            item = selected_item[0]
            values = result_tree.item(item, "values")
            result_id = values[0]
            
            if messagebox.askyesno("确认删除", f"确定要删除ID为{result_id}的记录吗？"):
                if self.delete_drawing_result(result_id):
                    # 从表格中移除
                    result_tree.delete(item)
                    messagebox.showinfo("成功", "删除成功")
        
        delete_button = ttk.Button(action_frame, text="删除", command=on_delete)
        delete_button.pack(side=tk.LEFT, padx=5)
        
        # 导出CSV按钮
        def on_export():
            # 使用现有的save_results方法导出CSV
            self.save_results()
        
        export_button = ttk.Button(action_frame, text="导出CSV", command=on_export)
        export_button.pack(side=tk.LEFT, padx=5)
        
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
        
        ttk.Button(bottom_frame, text="保存退出", command=lambda: self.save_config(close_window=True)).pack(side=tk.RIGHT, padx=5)
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
    
    def save_config(self, close_window=False):
        """保存配置
        
        Args:
            close_window: 是否在保存后关闭窗口，默认为True
        """
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
            # 先更新主窗口下拉框
            self.after_idle(lambda: self.main_app.refresh_ui())
            # 只有在close_window为True时才关闭窗口
            if close_window:
                self.after_idle(self.destroy)
            
        except Exception as e:
            messagebox.showerror("错误", f"保存配置失败: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = POCJudgeSelector(root)
    root.mainloop()
    