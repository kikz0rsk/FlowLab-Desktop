#pragma once

#include <QSyntaxHighlighter>
#include <QRegularExpression>
#include <QTextEdit>

class FlowlabSyntaxHighlighter : public QSyntaxHighlighter {
	std::vector<QRegularExpression> keywords;

	public:
		explicit FlowlabSyntaxHighlighter(QObject *parent) : QSyntaxHighlighter(parent)	{
			keywords.emplace_back (
				"[ -~]{2,}",
				QRegularExpression::PatternOption::CaseInsensitiveOption
			);
		}

		void highlightBlock(const QString& text) override	{
			QTextCharFormat highlightFormat;
			highlightFormat.setBackground(QBrush(QColor::fromRgb(252, 129, 74)));
			if (const auto textEdit = dynamic_cast<QTextEdit *>(parent()); textEdit) {
				const QFont font = textEdit->font();
				highlightFormat.setFont(font);
			}

			for (const QRegularExpression& regexp : std::as_const(keywords)) {
				QRegularExpressionMatchIterator matchIterator = regexp.globalMatch(text);
				while (matchIterator.hasNext()) {
					QRegularExpressionMatch match = matchIterator.next();
					setFormat(match.capturedStart(), match.capturedLength(), highlightFormat);
				}
			}
		}
};
