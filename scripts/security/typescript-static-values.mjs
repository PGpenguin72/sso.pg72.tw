import { API } from "typescript/unstable/sync";
import { createVirtualFileSystem } from "typescript/unstable/fs";
import { SyntaxKind } from "typescript/unstable/ast";

const MAX_STATIC_VALUE_CHARS = 4096;
const MAX_STATIC_EVALUATION_DEPTH = 16;
const MAX_STATIC_SEGMENTS = 64;

const virtualFileSystem = createVirtualFileSystem({});
const compiler = new API({ cwd: "/", fs: virtualFileSystem });
let sourceSequence = 0;
let previousSourceFile = null;

function sourceSuffix(relativePath) {
  const match = /\.(?:[cm]?[jt]sx?)$/i.exec(relativePath);
  return match?.[0].toLowerCase() ?? ".ts";
}

function boundedString(value, segments = 1) {
  if (value.length > MAX_STATIC_VALUE_CHARS || segments > MAX_STATIC_SEGMENTS) {
    return { status: "overflow" };
  }
  return { status: "static", value, segments };
}

function staticPrimitive(node, depth = 0) {
  if (!node || depth > MAX_STATIC_EVALUATION_DEPTH) return { status: "dynamic" };
  switch (node.kind) {
    case SyntaxKind.StringLiteral:
    case SyntaxKind.NoSubstitutionTemplateLiteral:
      return boundedString(node.text);
    case SyntaxKind.NumericLiteral: {
      const value = Number(node.text);
      return Number.isFinite(value)
        ? { status: "static", value, segments: 1 }
        : { status: "dynamic" };
    }
    case SyntaxKind.TrueKeyword:
      return { status: "static", value: true, segments: 1 };
    case SyntaxKind.FalseKeyword:
      return { status: "static", value: false, segments: 1 };
    case SyntaxKind.NullKeyword:
      return { status: "static", value: null, segments: 1 };
    case SyntaxKind.ParenthesizedExpression:
    case SyntaxKind.AsExpression:
    case SyntaxKind.SatisfiesExpression:
    case SyntaxKind.NonNullExpression:
    case SyntaxKind.TypeAssertionExpression:
      return staticPrimitive(node.expression, depth + 1);
    case SyntaxKind.PrefixUnaryExpression: {
      if (node.operator !== SyntaxKind.PlusToken && node.operator !== SyntaxKind.MinusToken) {
        return { status: "dynamic" };
      }
      const operand = staticPrimitive(node.operand, depth + 1);
      if (operand.status !== "static" || typeof operand.value !== "number") return operand;
      return {
        status: "static",
        value: node.operator === SyntaxKind.MinusToken ? -operand.value : operand.value,
        segments: operand.segments,
      };
    }
    case SyntaxKind.BinaryExpression: {
      if (node.operatorToken.kind !== SyntaxKind.PlusToken) return { status: "dynamic" };
      const left = staticPrimitive(node.left, depth + 1);
      const right = staticPrimitive(node.right, depth + 1);
      if (left.status === "overflow" || right.status === "overflow") {
        return { status: "overflow" };
      }
      if (left.status !== "static" || right.status !== "static") {
        return { status: "dynamic" };
      }
      const segments = left.segments + right.segments;
      if (typeof left.value === "string" || typeof right.value === "string") {
        return boundedString(String(left.value) + String(right.value), segments);
      }
      if (typeof left.value === "number" && typeof right.value === "number") {
        return { status: "static", value: left.value + right.value, segments };
      }
      return { status: "dynamic" };
    }
    case SyntaxKind.TemplateExpression: {
      let value = node.head.text;
      let segments = 1;
      for (const span of node.templateSpans) {
        const expression = staticPrimitive(span.expression, depth + 1);
        if (expression.status !== "static") return expression;
        value += String(expression.value) + span.literal.text;
        segments += expression.segments + 1;
        if (value.length > MAX_STATIC_VALUE_CHARS || segments > MAX_STATIC_SEGMENTS) {
          return { status: "overflow" };
        }
      }
      return boundedString(value, segments);
    }
    default:
      return { status: "dynamic" };
  }
}

function staticName(node) {
  if (!node) return null;
  switch (node.kind) {
    case SyntaxKind.Identifier:
    case SyntaxKind.PrivateIdentifier:
    case SyntaxKind.StringLiteral:
    case SyntaxKind.NoSubstitutionTemplateLiteral:
    case SyntaxKind.NumericLiteral:
      return node.text;
    case SyntaxKind.ComputedPropertyName: {
      const value = staticPrimitive(node.expression);
      return value.status === "static" ? String(value.value) : null;
    }
    case SyntaxKind.PropertyAccessExpression:
      return node.name.text;
    case SyntaxKind.ElementAccessExpression: {
      const value = staticPrimitive(node.argumentExpression);
      return value.status === "static" ? String(value.value) : null;
    }
    default:
      return null;
  }
}

function sideOf(parent, child) {
  if (parent.left === child) return "left";
  if (parent.right === child) return "right";
  if (parent.initializer === child) return "initializer";
  if (parent.expression === child) return "expression";
  if (parent.condition === child) return "condition";
  if (parent.whenTrue === child) return "when-true";
  if (parent.whenFalse === child) return "when-false";
  return "child";
}

function contextDescriptor(parent, child) {
  switch (parent.kind) {
    case SyntaxKind.VariableDeclaration:
      return `variable:${staticName(parent.name) ?? "dynamic"}:${sideOf(parent, child)}`;
    case SyntaxKind.PropertyAssignment:
    case SyntaxKind.PropertyDeclaration:
    case SyntaxKind.EnumMember:
      return `property:${staticName(parent.name) ?? "dynamic"}:${sideOf(parent, child)}`;
    case SyntaxKind.BinaryExpression:
      return `binary:${SyntaxKind[parent.operatorToken.kind]}:${sideOf(parent, child)}:${staticName(parent.left) ?? "expression"}`;
    case SyntaxKind.ConditionalExpression:
      return `conditional:${sideOf(parent, child)}`;
    case SyntaxKind.ReturnStatement:
      return "return:expression";
    case SyntaxKind.ExpressionStatement:
      return "statement:expression";
    default:
      return SyntaxKind[parent.kind];
  }
}

function staticContext(node) {
  const descriptors = [];
  let child = node;
  let parent = node.parent;
  while (parent && descriptors.length < 4 && parent.kind !== SyntaxKind.SourceFile) {
    descriptors.push(contextDescriptor(parent, child));
    child = parent;
    parent = parent.parent;
  }
  return descriptors.join(">");
}

function assignment(node) {
  switch (node.kind) {
    case SyntaxKind.VariableDeclaration:
    case SyntaxKind.PropertyAssignment:
    case SyntaxKind.PropertyDeclaration:
    case SyntaxKind.EnumMember:
    case SyntaxKind.BindingElement:
      if (!node.initializer) return null;
      return {
        assignmentKind: SyntaxKind[node.kind],
        expression: node.initializer,
        key: staticName(node.propertyName ?? node.name),
        keyKind: SyntaxKind[(node.propertyName ?? node.name).kind],
      };
    case SyntaxKind.BinaryExpression:
      if (
        node.operatorToken.kind < SyntaxKind.FirstAssignment ||
        node.operatorToken.kind > SyntaxKind.LastAssignment
      ) {
        return null;
      }
      return {
        assignmentKind: SyntaxKind[node.kind],
        expression: node.right,
        key: staticName(node.left),
        keyKind: SyntaxKind[node.left.kind],
      };
    default:
      return null;
  }
}

function staticValueForm(node) {
  switch (node.kind) {
    case SyntaxKind.StringLiteral:
      return "string-literal";
    case SyntaxKind.NoSubstitutionTemplateLiteral:
      return "no-substitution-template";
    case SyntaxKind.TemplateExpression:
      return "template-expression";
    case SyntaxKind.BinaryExpression:
      return node.operatorToken.kind === SyntaxKind.PlusToken ? "binary-plus" : null;
    default:
      return null;
  }
}

export function analyzeTypeScriptStaticValues(content, { relativePath = "scan.ts" } = {}) {
  const suffix = sourceSuffix(relativePath);
  const filename = `/pgid-secret-scan-${sourceSequence++}${suffix}`;
  if (previousSourceFile) virtualFileSystem.removeFile(previousSourceFile);
  virtualFileSystem.writeFile(filename, content);
  const snapshot = compiler.updateSnapshot({
    closeFiles: previousSourceFile ? [previousSourceFile] : undefined,
    fileChanges: {
      created: [filename],
      deleted: previousSourceFile ? [previousSourceFile] : undefined,
    },
    openFiles: [filename],
  });
  previousSourceFile = filename;
  try {
    const project = snapshot.getDefaultProjectForFile(filename);
    const sourceFile = project?.program.getSourceFile(filename);
    if (!project || !sourceFile) {
      return { assignments: [], parseErrors: 1, staticValues: [] };
    }
    const assignments = [];
    const staticValues = [];
    function visit(node) {
      const candidate = assignment(node);
      if (candidate?.key) {
        assignments.push({
          assignmentKind: candidate.assignmentKind,
          key: candidate.key,
          keyKind: candidate.keyKind,
          evaluation: staticPrimitive(candidate.expression),
          form: staticValueForm(candidate.expression) ?? "other",
        });
      }
      const form = staticValueForm(node);
      if (form) {
        const evaluation = staticPrimitive(node);
        if (evaluation.status === "static" && typeof evaluation.value === "string") {
          staticValues.push({
            context: staticContext(node),
            form,
            value: evaluation.value,
          });
        }
      }
      node.forEachChild(visit);
    }
    visit(sourceFile);
    return {
      assignments,
      parseErrors: project.program.getSyntacticDiagnostics(filename).length,
      staticValues,
    };
  } finally {
    snapshot.dispose();
  }
}
