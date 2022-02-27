use trace::debugger;
use std::{str, iter::Peekable};

use colored::Colorize;

use crate::expr::parse_expr;

macro_rules! command_not_found {
	($path:expr) => {
		eprintln!("{} - {} - try {} for help", format!("Command not found").red().bold(), $path,
			if $path.len() == 1 { "h".bold() }
			else { $path[0..$path.len() - 1].bold() }
		);
	};
}

macro_rules! syntax_error {
	($parsing:expr) => {
		eprintln!("{}", format!("Could not parse {}", $parsing).red().bold());
	};
}

pub enum OpType {
	Qword,
	Dword,
	Word,
	Byte
}

impl OpType {
	pub fn size(&self) -> usize {
		match self {
			OpType::Qword => 8,
			OpType::Dword => 4,
			OpType::Word => 2,
			OpType::Byte => 1,
		}
	}
}

pub struct CommandSegmentParser<'a> {
	segments: core::slice::Iter<'a, CommandSegment>,
	chars: Peekable<str::Chars<'a>>
}

impl<'a> CommandSegmentParser<'a> {
	pub fn new(segments: core::slice::Iter<'a, CommandSegment>, chars: str::Chars<'a>) -> CommandSegmentParser<'a> {
		CommandSegmentParser {
			segments,
			chars: chars.peekable()
		}
	}

	pub fn op_type(&mut self) -> Option<OpType> {
		match self.segments.next().expect("Expected OpType segment") {
			CommandSegment::OpType => {},
			_ => panic!("Not an OpType command segment")
		}

		match self.chars.next() {
			Some('q') => Some(OpType::Qword),
			Some('d') => Some(OpType::Dword),
			Some('w') => Some(OpType::Word),
			Some('b') => Some(OpType::Byte),
			_ => {
				syntax_error!("operand type");
				None
			}
		}
	}

	pub fn num(&mut self) -> Option<usize> {
		match self.segments.next().expect("Expected Num segment") {
			CommandSegment::Num => {},
			_ => panic!("Not a Num command segment")
		}

		while let Some(chr) = self.chars.peek() {
			if !chr.is_ascii_whitespace() { break }
			self.chars.next();
		}

		let mut string = String::new();
		while let Some(chr) = self.chars.peek() {
			if !chr.is_ascii_digit() { break }
			string.push(*chr);
			self.chars.next();
		}

		if string.len() == 0 {
			Some(1)
		} else {
			Some(string.parse().unwrap())
		}
	}

	pub fn expr(&mut self, debugger: &mut Option<debugger::Debugger>) -> Option<u64> {
		let name = match self.segments.next().expect("Expected Expr segment") {
			CommandSegment::Expr(name) => name,
			_ => panic!("Not an Expr command segment")
		};

		while let Some(chr) = self.chars.peek() {
			if !chr.is_ascii_whitespace() { break }
			self.chars.next();
		}

		match parse_expr(debugger, &mut self.chars) {
			Some(val) => Some(val),
			None => {
				syntax_error!(name);
				None
			}
		}
	}
}

pub enum CommandSegment {
	OpType,
	Num,
	Expr(String),
}

pub type Action = fn(&mut Option<debugger::Debugger>, CommandSegmentParser);

pub struct Command {
	chr: char,
	segments: Vec<CommandSegment>,
	description: Option<String>,
	action: Action
}

impl Command {
	pub fn new(chr: char, action: Action) -> Command {
		Command {
			chr,
			segments: Vec::new(),
			description: None,
			action
		}
	}

	pub fn describe<T: Into<String>>(mut self, description: T) -> Command {
		self.description = Some(description.into());
		self
	}

	pub fn op_type(mut self) -> Command {
		self.segments.push(CommandSegment::OpType);
		self
	}

	pub fn num(mut self) -> Command {
		self.segments.push(CommandSegment::Num);
		self
	}

	pub fn expr<T: Into<String>>(mut self, name: T) -> Command {
		self.segments.push(CommandSegment::Expr(name.into()));
		self
	}
}

impl CommandPart for Command {
    fn takes(&self, chr: Option<char>) -> bool {
        match chr {
			Some(chr) if chr == self.chr => true,
			_ => false
		}
    }

    fn parse_and_exec(&self, debugger: &mut Option<debugger::Debugger>, _parent_path: &str, _chr: char, chars: str::Chars) {
		// TODO test for `abh` to display help message
		(self.action)(debugger, CommandSegmentParser::new(self.segments.iter(), chars));
    }

	fn show_own_help(&self, parent_path: &str) {
		let mut form_string = String::new();

		for segment in self.segments.iter() {
			match segment {
				CommandSegment::OpType => form_string = format!("{}{}", form_string, "[qdwb]".red().bold()),
				CommandSegment::Num => form_string = format!("{}{}", form_string, "<num>".green().bold()),
				CommandSegment::Expr(name) => form_string = format!("{}{}", form_string, format!(" <{}>", name).green().bold()),
			}
		}

		if let Some(description) = &self.description {
			eprintln!("\t{}{}{} - {}", parent_path.yellow().bold(), self.chr.to_string().blue().bold(), form_string, description);
		} else {
			eprintln!("\t{}{}{}", parent_path.yellow().bold(), self.chr.to_string().blue().bold(), form_string);
		}
	}

	fn parse_and_show_help(&self, parent_path: &str, _chr: char, _chars: str::Chars) {
		self.show_own_help(parent_path)
	}
}

trait CommandPart {
	fn takes(&self, chr: Option<char>) -> bool;
	fn parse_and_exec(&self, debugger: &mut Option<debugger::Debugger>, parent_path: &str, chr: char, chars: str::Chars);
	fn show_own_help(&self, parent_path: &str);
	fn parse_and_show_help(&self, parent_path: &str, chr: char, chars: str::Chars);
}

pub struct Namespace {
	chr: char,
	name: String,
	description: Option<String>,
	commands: Vec<Box<dyn CommandPart>>
}

impl Namespace {
	pub fn new<T: Into<String>>(chr: char, name: T) -> Namespace {
		Namespace {
			chr,
			name: name.into(),
			description: None,
			commands: Vec::new()
		}
	}

	pub fn ns(mut self, ns: Namespace) -> Namespace {
		self.commands.push(Box::new(ns));
		self
	}

	pub fn cmd(mut self, cmd: Command) -> Namespace {
		self.commands.push(Box::new(cmd));
		self
	}

	pub fn describe<T: Into<String>>(mut self, description: T) -> Namespace {
		self.description = Some(description.into());
		self
	}

	fn show_full_help(&self, parent_path: &str) {
		if let Some(description) = &self.description {
			eprintln!("{}{} - {} - {}", parent_path.yellow().bold(), self.chr.to_string().blue().bold(), self.name.bold(), description);
		} else {
			eprintln!("{}{} - {}", parent_path.yellow().bold(), self.chr.to_string().blue().bold(), self.name.bold());
		}

		let path = format!("{}{}", parent_path, self.chr);
		for command in self.commands.iter() {
			command.show_own_help(&path);
		}
	}
}

impl CommandPart for Namespace {
    fn takes(&self, chr: Option<char>) -> bool {
        match chr {
			Some(chr) if chr == self.chr => true,
			_ => false
		}
    }

    fn parse_and_exec(&self, debugger: &mut Option<debugger::Debugger>, parent_path: &str, _chr: char, mut chars: str::Chars) {
		if let Some(chr) = chars.next() {
			if chr == 'h' {
				self.show_full_help(&parent_path);
				return;
			}

			let parent_path = format!("{}{}", parent_path, self.chr);

			for command in self.commands.iter() {
				if command.takes(Some(chr)) {
					command.parse_and_exec(debugger, &parent_path, chr, chars);
					return;
				}
			}

			command_not_found!(format!("{}{}", parent_path, chr));
		} else {
			self.show_full_help(&parent_path);
		}
    }

	fn show_own_help(&self, parent_path: &str) {
		eprintln!("\t{}{} - {}", parent_path.yellow().bold(), self.chr.to_string().blue().bold(), self.name);
	}

	fn parse_and_show_help(&self, parent_path: &str, _chr: char, mut chars: str::Chars) {
		if let Some(next_chr) = chars.next() {
			if next_chr == 'h' {
				self.show_full_help(&parent_path);
				return;
			}

			let path = format!("{}{}", parent_path, self.chr);

			for command in self.commands.iter() {
				if command.takes(Some(next_chr)) {
					command.parse_and_show_help(&path, next_chr, chars);
					return;
				}
			}

			command_not_found!(format!("{}{}", path, next_chr));
		} else {
			self.show_full_help(&parent_path);
		}
	}
}

pub struct CommandSet {
	commands: Vec<Box<dyn CommandPart>>
}

impl CommandSet {
	pub fn new() -> CommandSet {
		CommandSet {
			commands: Vec::new()
		}
	}

	pub fn ns(mut self, ns: Namespace) -> CommandSet {
		self.commands.push(Box::new(ns));
		self
	}

	pub fn cmd(mut self, cmd: Command) -> CommandSet {
		self.commands.push(Box::new(cmd));
		self
	}

	fn show_help_for(&self,  mut chars: str::Chars) {
		if let Some(root_chr) = chars.next() {
			for command in self.commands.iter() {
				if command.takes(Some(root_chr)) {
					command.parse_and_show_help("", root_chr, chars);
					return;
				}
			}

			command_not_found!(format!("{}", root_chr));
		} else {
			for command in self.commands.iter() {
				command.show_own_help("");
			}
		}
	}

	pub fn parse_and_exec(&self, debugger: &mut Option<debugger::Debugger>, command: &str) {
		if command.len() == 0 { return; }

		let mut chars = command.chars();

		let root_chr =  chars.next().unwrap();
		if root_chr == 'h' {
			self.show_help_for(chars);
			return;
		}

		for command in self.commands.iter() {
			if command.takes(Some(root_chr)) {
				command.parse_and_exec(debugger, "", root_chr, chars);
				return;
			}
		}

		command_not_found!(&command[0..1]);
	}
}