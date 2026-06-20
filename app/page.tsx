import { WorkflowDashboard } from "./components/WorkflowDashboard";
import { createSampleEngagement, sampleCode } from "@/lib/sample-engagement";
import path from "path";

export default function Home() {
  return (
    <WorkflowDashboard
      engagement={createSampleEngagement()}
      sampleCode={sampleCode}
      defaultRootPath={path.join(process.cwd(), "data", "fixtures")}
    />
  );
}
