#pragma once

#include <QSyntaxHighlighter>
#include <QRegularExpression>
#include <QTextEdit>

class FlowlabSyntaxHighlighter : public QSyntaxHighlighter {
	std::vector<QRegularExpression> keywords;

	public:
		explicit FlowlabSyntaxHighlighter(QObject *parent);

		void highlightBlock(const QString& text) override;
};
